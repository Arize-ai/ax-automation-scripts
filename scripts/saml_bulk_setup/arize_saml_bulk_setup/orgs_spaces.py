"""Org and space resolution with in-memory caches.

All org/space CRUD goes through the REST API (`/v2/organizations`, `/v2/spaces`).
`arize_toolkit.Client` is still constructed because SAML operations
(getSAMLIdP, createSAMLIdP, updateSAMLIdP) have no REST equivalent in the spec
and we route them through the toolkit's authenticated GraphQL client via
`execute_graphql`. Toolkit construction also doubles as a fail-fast auth check.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

import requests
from arize_toolkit import Client as ArizeClient

from .config import ARIZE_APP_URL, ARIZE_REST_API_URL
from .retry import with_retry


class OrgSpaceService:
    """Resolve Arize organizations and spaces by name, creating them on demand.

    Uses the REST API for all org/space CRUD. Retains an `arize_toolkit.Client`
    only to expose its authenticated GraphQL transport (`_graphql_client`) via
    `execute_graphql`, which the SAML service uses for operations that have no
    REST equivalent.
    """

    def __init__(
        self,
        api_key: str,
        logger: logging.Logger,
        dry_run: bool,
        arize_app_url: str = ARIZE_APP_URL,
        arize_rest_url: str = ARIZE_REST_API_URL,
    ) -> None:
        self._logger = logger
        self._dry_run = dry_run

        # REST transport: every org/space op goes through this.
        self._rest_url = arize_rest_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        # Toolkit retained solely for SAML GraphQL transport. Its constructor
        # eagerly calls get_all_organizations() — bad key fails fast here,
        # before any row runs.
        self._toolkit = ArizeClient(
            arize_developer_key=api_key,
            arize_app_url=arize_app_url,
        )

        self._org_cache: dict[str, str] = {}  # org_name → org_id
        self._org_cache_loaded = False
        self._space_cache: dict[tuple[str, str], str] = {}  # (org_id, name) → space_id
        self._spaces_loaded_for: set[str] = set()

        # Failure caches: once we've failed to create a given org/space, future
        # rows that reference the same name should short-circuit with the same
        # error instead of re-hitting a known-broken API call.
        self._org_create_failures: dict[str, str] = {}  # org_name → error message
        self._space_create_failures: dict[tuple[str, str], str] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def execute_graphql(
        self, query: Any, variable_values: dict[str, Any], operation_name: str
    ) -> Any:
        """Run a raw GraphQL operation via the toolkit's authenticated transport.

        Exposed for SAML operations that have no REST equivalent. Encapsulates
        the toolkit's private `_graphql_client` access in one place — if the
        toolkit ever renames that attribute, only this method needs to change.
        """
        return with_retry(
            lambda: self._toolkit._graphql_client.execute(
                query, variable_values=variable_values
            ),
            operation_name,
            self._logger,
        )

    def resolve_org(self, org_name: str) -> tuple[str, str]:
        """Return (org_id, status). Creates the org if it doesn't exist.

        Raises RuntimeError on a repeated create failure for the same org name
        (without re-hitting the API) so consecutive rows don't all retry the
        same broken call.
        """
        self._load_all_organizations()

        if org_name in self._org_cache:
            return self._org_cache[org_name], "already_exists"

        if org_name in self._org_create_failures:
            raise RuntimeError(
                f"Earlier attempt to create organization '{org_name}' failed: "
                f"{self._org_create_failures[org_name]}"
            )

        self._logger.info("Creating organization: %s", org_name)
        if self._dry_run:
            fake_id = f"__dry_run_org_{org_name}__"
            self._org_cache[org_name] = fake_id
            self._logger.info("[DRY RUN] Would create organization: %s", org_name)
            return fake_id, "dry_run"

        try:
            org = self._post("/v2/organizations", {"name": org_name})
        except Exception as exc:
            self._org_create_failures[org_name] = str(exc)
            raise
        self._org_cache[org["name"]] = org["id"]
        return org["id"], "created"

    def resolve_space(
        self, org_id: str, org_name: str, space_name: str
    ) -> tuple[str, str]:
        """Return (space_id, status). Creates the space if it doesn't exist.

        Raises RuntimeError on a repeated create failure for the same
        (org_id, space_name) (without re-hitting the API) so consecutive
        rows don't all retry the same broken call.
        """
        self._load_spaces_for_org(org_id, org_name)

        cache_key = (org_id, space_name)
        if cache_key in self._space_cache:
            return self._space_cache[cache_key], "already_exists"

        if cache_key in self._space_create_failures:
            raise RuntimeError(
                f"Earlier attempt to create space '{space_name}' in org "
                f"'{org_name}' failed: {self._space_create_failures[cache_key]}"
            )

        self._logger.info("Creating space '%s' in org '%s'…", space_name, org_name)
        if self._dry_run:
            fake_id = f"__dry_run_space_{space_name}__"
            self._space_cache[cache_key] = fake_id
            self._logger.info("[DRY RUN] Would create space: %s", space_name)
            return fake_id, "dry_run"

        try:
            space = self._post(
                "/v2/spaces",
                {"name": space_name, "organization_id": org_id},
            )
        except Exception as exc:
            self._space_create_failures[cache_key] = str(exc)
            raise
        self._space_cache[(org_id, space["name"])] = space["id"]
        return space["id"], "created"

    def space_id_to_name(self) -> dict[str, str]:
        """Reverse lookup for error/preflight messages."""
        return {sid: name for (_, name), sid in self._space_cache.items()}

    # ── Internals ─────────────────────────────────────────────────────────────

    def _load_all_organizations(self) -> None:
        """Populate the org_name → org_id cache via paginated REST. Idempotent."""
        if self._org_cache_loaded:
            return
        self._logger.debug("Loading all organizations…")
        for org in self._get_paginated("/v2/organizations", "organizations", {}):
            name = org.get("name")
            org_id = org.get("id")
            if not name or not org_id:
                continue
            self._org_cache[name] = org_id
            self._logger.debug("  org: %s (%s)", name, org_id)
        self._org_cache_loaded = True

    def _load_spaces_for_org(self, org_id: str, org_name: str) -> None:
        """Populate the (org_id, space_name) → space_id cache for one org. Idempotent."""
        if org_id in self._spaces_loaded_for:
            return
        if org_id.startswith("__dry_run_"):
            # Org only exists as a dry-run placeholder — no real ID to query.
            self._spaces_loaded_for.add(org_id)
            return
        self._logger.debug("Loading spaces for org '%s'…", org_name)

        for space in self._get_paginated("/v2/spaces", "spaces", {"org_id": org_id}):
            name = space.get("name")
            sid = space.get("id")
            if not name or not sid:
                continue
            self._space_cache[(org_id, name)] = sid
            self._logger.debug("  space: %s (%s)", name, sid)
        self._spaces_loaded_for.add(org_id)

    def _get_paginated(
        self, path: str, items_key: str, params: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        """Iterate items from a paginated GET, following `pagination.next_cursor`.

        `items_key` is the field on the response that holds the page's list
        (e.g. "organizations", "spaces"). Each page fetch goes through
        `with_retry` so 429s back off and retry.
        """
        url = f"{self._rest_url}{path}"
        cursor: str | None = None
        while True:
            page_params: dict[str, Any] = {"limit": 100, **params}
            if cursor:
                page_params["cursor"] = cursor

            # raise_for_status() inside the lambda so a 429 surfaces as an
            # exception that with_retry can detect; otherwise requests.get
            # returns the 429 response object and the rate-limit check fires
            # after with_retry has already returned (i.e. no retry).
            def fetch_page() -> requests.Response:
                r = requests.get(
                    url, headers=self._headers, params=page_params, timeout=30
                )
                r.raise_for_status()
                return r

            resp = with_retry(fetch_page, f"GET {path}", self._logger)
            payload = resp.json()
            for item in payload.get(items_key) or []:
                yield item
            pagination = payload.get("pagination") or {}
            if not pagination.get("has_more"):
                return
            cursor = pagination.get("next_cursor")
            if not cursor:
                # Defensive: has_more=true but no cursor — avoid infinite loop.
                return

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST JSON to `path`, raise on non-2xx, return parsed JSON."""
        url = f"{self._rest_url}{path}"

        def post() -> requests.Response:
            r = requests.post(url, headers=self._headers, json=body, timeout=30)
            r.raise_for_status()
            return r

        resp = with_retry(post, f"POST {path}", self._logger)
        return resp.json()
