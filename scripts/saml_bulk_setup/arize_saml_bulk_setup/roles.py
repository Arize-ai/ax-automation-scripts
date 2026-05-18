"""Lazy cache of account-level custom roles for space-role resolution."""

from __future__ import annotations

import logging
from typing import Any

import requests

from .config import ARIZE_REST_API_URL
from .legacy_role_permissions import LEGACY_ROLE_EQUIVALENTS
from .retry import with_retry


class RolesCache:
    """Resolve non-builtin space-role values to relay role IDs.

    Loaded once on first reference via the REST endpoint `GET /v2/roles`,
    which returns both predefined and custom roles for the authenticated
    account. The cache is only consulted when the CSV value didn't match
    a builtin alias upstream.
    """

    def __init__(self, api_key: str, logger: logging.Logger) -> None:
        self._api_key = api_key
        self._logger = logger
        self._name_to_id: dict[str, str] = {}
        self._role_ids: set[str] = set()
        self._loaded = False

    def resolve_custom_space_role(self, role_value: str) -> str:
        """Resolve a non-builtin space role to a relay role ID.

        Accepts either a role name (looked up case-insensitively) or a relay
        global ID (validated against the cache).
        """
        self._ensure_loaded()
        # Relay role IDs are base64 of "Role:<int>" → all start with "Um9sZTo".
        if role_value.startswith("Um9sZTo") and role_value in self._role_ids:
            return role_value
        rid = self._name_to_id.get(role_value.lower())
        if rid:
            return rid
        available = ", ".join(sorted(self._name_to_id.keys())) or "(none)"
        raise ValueError(
            f"Custom role '{role_value}' not found in this account. "
            f"Available roles (case-insensitive): {available}"
        )

    def ensure_legacy_equivalent_role(self, legacy_role_key: str) -> tuple[str, str]:
        """Get-or-create the custom role mirroring a legacy space role.

        `legacy_role_key` is the GraphQL form: "admin" | "member" | "readOnly" |
        "annotator". Returns `(relay_role_id, custom_role_name)`.

        Idempotent: first checks the cache, then POSTs if missing, and on a 409
        race condition re-reads the cache to recover the concurrently created
        role's ID.
        """
        if legacy_role_key not in LEGACY_ROLE_EQUIVALENTS:
            raise ValueError(
                f"No legacy-equivalent permission set defined for '{legacy_role_key}'. "
                f"Known keys: {sorted(LEGACY_ROLE_EQUIVALENTS.keys())}"
            )
        name, description, permissions = LEGACY_ROLE_EQUIVALENTS[legacy_role_key]

        self._ensure_loaded()
        cached_id = self._name_to_id.get(name.lower())
        if cached_id:
            return cached_id, name

        relay_id = self._post_role(name, description, permissions)
        if relay_id:
            self._name_to_id[name.lower()] = relay_id
            self._role_ids.add(relay_id)
            self._logger.info(
                "Auto-created custom role '%s' (id=%s) as legacy-%s equivalent",
                name,
                relay_id,
                legacy_role_key,
            )
            return relay_id, name

        # 409 race: someone else just created the role. Reload and look it up.
        self._loaded = False
        self._name_to_id.clear()
        self._role_ids.clear()
        self._ensure_loaded()
        racy_id = self._name_to_id.get(name.lower())
        if not racy_id:
            raise RuntimeError(
                f"POST /v2/roles for '{name}' returned 409 (already exists) but the "
                "role wasn't visible after a cache reload. Re-run the script."
            )
        return racy_id, name

    def _post_role(
        self, name: str, description: str, permissions: list[str]
    ) -> str | None:
        """POST /v2/roles. Returns the new role's relay ID, or None on 409 Conflict."""
        url = f"{ARIZE_REST_API_URL}/v2/roles"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        body = {"name": name, "description": description, "permissions": permissions}

        def post_role() -> requests.Response:
            r = requests.post(url, headers=headers, json=body, timeout=30)
            # 409 means the role already exists (race). Don't raise — let the
            # caller fall through to a cache reload to recover the ID.
            if r.status_code == 409:
                return r
            r.raise_for_status()
            return r

        resp = with_retry(post_role, f"POST /v2/roles ({name})", self._logger)
        if resp.status_code == 409:
            return None
        payload = resp.json() or {}
        # The endpoint may return the role under different shapes: {"role": {...}}
        # or {"id": "...", "name": "..."}. Handle both.
        role = payload.get("role") if isinstance(payload.get("role"), dict) else payload
        rid = role.get("id") or ""
        if not rid:
            raise RuntimeError(
                f"POST /v2/roles for '{name}' returned no id in response: {payload}"
            )
        return rid

    def _ensure_loaded(self) -> None:
        """Populate the account-role cache via paginated GET /v2/roles. Idempotent."""
        if self._loaded:
            return
        self._logger.debug("Loading account roles for custom-role lookup…")
        url = f"{ARIZE_REST_API_URL}/v2/roles"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 100}
            if cursor:
                params["cursor"] = cursor

            # raise_for_status() inside the lambda so a 429 surfaces as an
            # exception that with_retry can detect; otherwise requests.get
            # returns the 429 response object and the rate-limit check fires
            # after with_retry has already returned (i.e. no retry).
            def fetch_page() -> requests.Response:
                r = requests.get(url, headers=headers, params=params, timeout=30)
                r.raise_for_status()
                return r

            resp = with_retry(fetch_page, "GET /v2/roles", self._logger)
            payload = resp.json()
            for role in payload.get("roles") or []:
                rid = role.get("id") or ""
                name = role.get("name") or ""
                if not rid or not name:
                    continue
                self._name_to_id[name.lower()] = rid
                self._role_ids.add(rid)
            pagination = payload.get("pagination") or {}
            if not pagination.get("has_more"):
                break
            cursor = pagination.get("next_cursor")
            if not cursor:
                # Defensive: has_more=true but no cursor returned — avoid infinite loop.
                break
        self._loaded = True
        self._logger.debug("  loaded %d account role(s)", len(self._name_to_id))
