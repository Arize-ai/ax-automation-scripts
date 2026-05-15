"""Lazy cache of account-level custom roles for space-role resolution."""

from __future__ import annotations

import logging
from typing import Any

import requests

from .config import ARIZE_REST_API_URL
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
