"""
Reverse Proxy for Custom Model Endpoints.

Transparently forwards requests from Arize to a customer's LLM gateway,
handling token acquisition and refresh automatically. Supports streaming
(SSE) responses required by LLM endpoints.

See README.md for configuration and deployment instructions.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
import time
from typing import Generator

import requests
from flask import Flask, Response, jsonify, request

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("reverse-proxy")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_BASE_URL = os.environ.get("TARGET_BASE_URL", "").rstrip("/")
AUTH_TYPE = os.environ.get("AUTH_TYPE", "none").lower()
PROXY_AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN", "")
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "120"))

# Debug: capture incoming requests (and upstream status) to inspect what the
# client is sending. Set DUMP_REQUESTS=1 to log; set DUMP_REQUESTS_FILE to also
# append each request as a JSON line to a file.
DUMP_REQUESTS = os.environ.get("DUMP_REQUESTS", "").lower() in ("1", "true", "yes")
DUMP_REQUESTS_FILE = os.environ.get("DUMP_REQUESTS_FILE", "")

CLIENT_CERT_PATH = os.environ.get("CLIENT_CERT_PATH", "")
CLIENT_KEY_PATH = os.environ.get("CLIENT_KEY_PATH", "")

_STRIPPED_HEADERS = frozenset({
    # Hop-by-hop (RFC 2616)
    "host", "connection", "keep-alive", "transfer-encoding",
    "te", "trailers", "upgrade", "proxy-authorization", "proxy-authenticate",
    # Replaced by proxy with the upstream token
    "authorization",
    # Recomputed by the requests library from body length
    "content-length",
})

# ---------------------------------------------------------------------------
# Token providers
# ---------------------------------------------------------------------------


class TokenProvider:
    """Base class -- subclasses implement fetch_token()."""

    def fetch_token(self) -> tuple[str, float]:
        """Return (token, expires_at_epoch). expires_at=0 means never expires."""
        raise NotImplementedError


class StaticTokenProvider(TokenProvider):
    def __init__(self) -> None:
        self._token = os.environ.get("STATIC_BEARER_TOKEN", "")
        if not self._token:
            raise ValueError("STATIC_BEARER_TOKEN must be set when AUTH_TYPE=static")

    def fetch_token(self) -> tuple[str, float]:
        return self._token, 0


class OAuth2TokenProvider(TokenProvider):
    """Client-credentials grant (works with Okta, Auth0, Keycloak, etc.)."""

    def __init__(self) -> None:
        self._token_url = os.environ.get("OAUTH2_TOKEN_URL", "")
        self._client_id = os.environ.get("OAUTH2_CLIENT_ID", "")
        self._client_secret = os.environ.get("OAUTH2_CLIENT_SECRET", "")
        self._scope = os.environ.get("OAUTH2_SCOPE", "")
        if not self._token_url:
            raise ValueError("OAUTH2_TOKEN_URL must be set when AUTH_TYPE=oauth2")
        if not self._client_id or not self._client_secret:
            raise ValueError("OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET must be set")

    def fetch_token(self) -> tuple[str, float]:
        data: dict[str, str] = {"grant_type": "client_credentials"}
        if self._scope:
            data["scope"] = self._scope
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                resp = requests.post(
                    self._token_url,
                    data=data,
                    auth=(self._client_id, self._client_secret),
                    timeout=30,
                )
                resp.raise_for_status()
                body = resp.json()
                token = body.get("access_token")
                if not token:
                    raise ValueError(
                        f"Token response missing 'access_token': {list(body.keys())}"
                    )
                expires_in = body.get("expires_in", 3600)
                expires_at = time.time() + max(expires_in - 60, 30)
                return token, expires_at
            except requests.RequestException as exc:
                last_exc = exc
                if attempt == 0:
                    log.warning("Token fetch attempt %d failed: %s", attempt + 1, exc)
                    time.sleep(1)
        raise last_exc  # type: ignore[misc]


class AzureTokenProvider(TokenProvider):
    def __init__(self) -> None:
        from azure.identity import ClientSecretCredential

        tenant = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
        if not all([tenant, client_id, client_secret]):
            raise ValueError(
                "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET must all be set"
            )
        self._credential = ClientSecretCredential(tenant, client_id, client_secret)
        self._scope = os.environ.get(
            "AZURE_SCOPE", "https://cognitiveservices.azure.com/.default"
        )

    def fetch_token(self) -> tuple[str, float]:
        tok = self._credential.get_token(self._scope)
        return tok.token, tok.expires_on


class CachedTokenProvider:
    """Thread-safe wrapper that caches a token until near expiry.

    Uses a single tuple for cache state so assignment is atomic in CPython,
    avoiding a window where another thread sees a new token with an old expiry.
    """

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider
        self._lock = threading.Lock()
        self._cache: tuple[str, float] = ("", 0)

    def get_token(self) -> str:
        token, expires_at = self._cache
        if token and (expires_at == 0 or time.time() < expires_at):
            return token
        with self._lock:
            token, expires_at = self._cache
            if token and (expires_at == 0 or time.time() < expires_at):
                return token
            log.info("Refreshing token via %s", type(self._provider).__name__)
            self._cache = self._provider.fetch_token()
            return self._cache[0]


class _NoopProvider:
    """Pass-through -- no authorization header added to upstream requests."""

    @staticmethod
    def get_token() -> str | None:
        return None


def _build_token_provider() -> CachedTokenProvider | _NoopProvider:
    providers = {
        "oauth2": OAuth2TokenProvider,
        "azure": AzureTokenProvider,
        "static": StaticTokenProvider,
    }
    if AUTH_TYPE == "none":
        return _NoopProvider()
    cls = providers.get(AUTH_TYPE)
    if cls is None:
        raise ValueError(
            f"Unsupported AUTH_TYPE={AUTH_TYPE!r}. "
            f"Choose from: {', '.join(['none'] + list(providers))}"
        )
    return CachedTokenProvider(cls())


token_provider = _build_token_provider()

# ---------------------------------------------------------------------------
# Upstream HTTP session (connection pooling, TLS)
# ---------------------------------------------------------------------------


def _build_session() -> requests.Session:
    s = requests.Session()
    if CLIENT_CERT_PATH and CLIENT_KEY_PATH:
        s.cert = (CLIENT_CERT_PATH, CLIENT_KEY_PATH)
    elif CLIENT_CERT_PATH:
        s.cert = CLIENT_CERT_PATH
    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE", "")
    if ca_bundle:
        s.verify = ca_bundle
    return s


upstream_session = _build_session()

# ---------------------------------------------------------------------------
# Health / readiness probes
# ---------------------------------------------------------------------------


@app.route("/healthz", methods=["GET"])
@app.route("/ready", methods=["GET"])
def health():
    if not TARGET_BASE_URL:
        return jsonify({"status": "misconfigured", "error": "TARGET_BASE_URL not set"}), 503
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------------------
# Incoming auth (optional -- validates requests from Arize)
# ---------------------------------------------------------------------------


@app.before_request
def check_proxy_auth():
    if request.path in ("/healthz", "/ready"):
        return None
    if not PROXY_AUTH_TOKEN:
        return None
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization: Bearer <token>"}), 401
    if not hmac.compare_digest(auth[7:].strip(), PROXY_AUTH_TOKEN):
        return jsonify({"error": "Invalid proxy auth token"}), 401
    return None


# ---------------------------------------------------------------------------
# Transparent reverse proxy (catch-all)
# ---------------------------------------------------------------------------


_REDACT_HEADERS = frozenset({"authorization", "proxy-authorization", "api-key", "x-api-key"})


def _dump_request(path: str, target_url: str) -> None:
    """Log the incoming request (and where it will be forwarded) for debugging."""
    if not DUMP_REQUESTS and not DUMP_REQUESTS_FILE:
        return

    headers = {}
    for key, value in request.headers:
        headers[key] = "***REDACTED***" if key.lower() in _REDACT_HEADERS else value

    raw = request.get_data()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        body = f"<{len(raw)} bytes of binary data>"

    record = {
        "method": request.method,
        "incoming_path": "/" + path,
        "query_string": request.query_string.decode("utf-8"),
        "forwarded_to": target_url,
        "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
        "content_type": request.content_type,
        "content_length": len(raw),
        "headers": headers,
        "body": body,
    }

    if DUMP_REQUESTS:
        log.info("INCOMING REQUEST:\n%s", json.dumps(record, indent=2))

    if DUMP_REQUESTS_FILE:
        try:
            with open(DUMP_REQUESTS_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            log.warning("Could not write to DUMP_REQUESTS_FILE %s: %s", DUMP_REQUESTS_FILE, exc)


def _stream_upstream(resp: requests.Response) -> Generator[bytes, None, None]:
    """Yield chunks from the upstream response, supporting SSE streams."""
    try:
        for chunk in resp.iter_content(chunk_size=4096):
            if chunk:
                yield chunk
    finally:
        resp.close()


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(path: str):
    if not TARGET_BASE_URL:
        return jsonify({"error": "TARGET_BASE_URL not configured"}), 503

    url = f"{TARGET_BASE_URL}/{path}" if path else f"{TARGET_BASE_URL}/"
    qs = request.query_string.decode("utf-8")
    if qs:
        url = f"{url}?{qs}"

    _dump_request(path, url)

    headers: dict[str, str] = {}
    for key, value in request.headers:
        if key.lower() not in _STRIPPED_HEADERS:
            headers[key] = value

    try:
        token = token_provider.get_token()
    except Exception as exc:
        log.error("Failed to obtain upstream auth token: %s", exc)
        return jsonify({"error": "Failed to obtain upstream auth token"}), 502

    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = request.get_data()

    log.debug("-> %s %s", request.method, url)

    try:
        upstream_resp = upstream_session.request(
            method=request.method,
            url=url,
            headers=headers,
            data=body,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            allow_redirects=False,
        )
    except requests.ConnectionError as exc:
        log.error("Connection to upstream failed: %s", exc)
        return jsonify({"error": "Cannot connect to upstream"}), 502
    except requests.Timeout:
        log.error("Upstream request timed out after %ss", REQUEST_TIMEOUT)
        return jsonify({"error": "Upstream request timed out"}), 504
    except requests.RequestException as exc:
        log.error("Upstream request failed: %s", exc)
        return jsonify({"error": "Upstream request failed"}), 502

    # requests' iter_content() transparently decompresses the body, so the
    # bytes we re-stream are already decoded. Drop content-encoding (else the
    # client tries to gunzip plaintext) and content-length (now wrong) and let
    # the response be sent chunked.
    resp_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in (
            "transfer-encoding", "connection", "keep-alive",
            "content-encoding", "content-length",
        )
    }

    if DUMP_REQUESTS and upstream_resp.status_code >= 400:
        log.warning("UPSTREAM RETURNED %s for %s", upstream_resp.status_code, url)
    log.debug("<- %s %s", upstream_resp.status_code, url)

    return Response(
        _stream_upstream(upstream_resp),
        status=upstream_resp.status_code,
        headers=resp_headers,
        content_type=upstream_resp.headers.get("Content-Type"),
    )


# ---------------------------------------------------------------------------
# Entrypoint (development only -- production uses gunicorn via Dockerfile)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    log.info("Reverse Proxy starting on :%d (dev mode)", port)
    log.info("  TARGET_BASE_URL : %s", TARGET_BASE_URL or "(NOT SET)")
    log.info("  AUTH_TYPE       : %s", AUTH_TYPE)
    log.info("  PROXY_AUTH_TOKEN: %s", "set" if PROXY_AUTH_TOKEN else "not set")
    log.info("  Client cert     : %s", "configured" if CLIENT_CERT_PATH else "none")
    if not TARGET_BASE_URL:
        log.warning("TARGET_BASE_URL is not set -- proxy will return 503 for all requests.")
    app.run(host="0.0.0.0", port=port)