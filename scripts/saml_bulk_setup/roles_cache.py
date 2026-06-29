"""Custom RBAC role resolution and caching for saml_bulk_setup."""

from __future__ import annotations

import logging
from typing import Any

import requests

from utils import with_retry

ARIZE_REST_API_URL = "https://api.arize.com"

# Used to auto-create custom RBAC roles mirroring legacy space roles when a
# same-space conflict forces promotion. Keys are the GraphQL form after
# _ROLE_ALIAS translation: "admin" | "member" | "readOnly" | "annotator".

LEGACY_ROLE_EQUIVALENTS: dict[str, tuple[str, str, list[str]]] = {
    "admin": (
        "Space Admin",
        "Auto-created by saml_bulk_setup to mirror the legacy Admin space role.",
        [
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "ML_MODEL_CREATE",
            "ML_MODEL_UPDATE",
            "ML_MODEL_DELETE",
            "PROJECT_CREATE",
            "PROJECT_UPDATE",
            "PROJECT_SPAN_CREATE",
            "PROJECT_SPAN_UPDATE",
            "PROJECT_SPAN_ANNOTATE",
            "PROJECT_SPAN_DELETE",
            "DATASET_CREATE",
            "DATASET_UPDATE",
            "DATASET_DELETE",
            "DATASET_EXAMPLE_CREATE",
            "DATASET_EXAMPLE_UPDATE",
            "DATASET_EXAMPLE_DELETE",
            "DATASET_EXAMPLE_ANNOTATE",
            "EXPERIMENT_CREATE",
            "EXPERIMENT_UPDATE",
            "EXPERIMENT_DELETE",
            "EXPERIMENT_RUN_ANNOTATE",
            "ANNOTATION_CONFIG_CREATE",
            "ANNOTATION_CONFIG_DELETE",
            "SPACE_UPDATE",
            "SPACE_DELETE",
            "ROLE_BINDING_READ",
            "ROLE_BINDING_CREATE",
            "ROLE_BINDING_DELETE",
            "QUEUE_CREATE",
            "QUEUE_UPDATE",
            "QUEUE_DELETE",
            "QUEUE_RECORD_ANNOTATE",
            "QUEUE_RECORD_CREATE",
            "QUEUE_RECORD_UPDATE",
            "QUEUE_RECORD_DELETE",
            "PROJECT_RESTRICT",
            "SERVICE_KEY_CREATE",
            "SERVICE_KEY_READ",
            "SERVICE_KEY_DELETE",
        ],
    ),
    "member": (
        "Space Member",
        "Auto-created by saml_bulk_setup to mirror the legacy Member space role.",
        [
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "ML_MODEL_CREATE",
            "ML_MODEL_UPDATE",
            "PROJECT_CREATE",
            "PROJECT_UPDATE",
            "PROJECT_SPAN_CREATE",
            "PROJECT_SPAN_UPDATE",
            "PROJECT_SPAN_ANNOTATE",
            "DATASET_CREATE",
            "DATASET_UPDATE",
            "DATASET_DELETE",
            "DATASET_EXAMPLE_CREATE",
            "DATASET_EXAMPLE_UPDATE",
            "DATASET_EXAMPLE_DELETE",
            "DATASET_EXAMPLE_ANNOTATE",
            "EXPERIMENT_CREATE",
            "EXPERIMENT_UPDATE",
            "EXPERIMENT_DELETE",
            "EXPERIMENT_RUN_ANNOTATE",
            "ANNOTATION_CONFIG_CREATE",
            "ANNOTATION_CONFIG_DELETE",
            "QUEUE_CREATE",
            "QUEUE_UPDATE",
            "QUEUE_DELETE",
            "QUEUE_RECORD_ANNOTATE",
            "QUEUE_RECORD_CREATE",
            "QUEUE_RECORD_UPDATE",
            "QUEUE_RECORD_DELETE",
            "SERVICE_KEY_CREATE",
            "SERVICE_KEY_READ",
            "SERVICE_KEY_DELETE",
        ],
    ),
    "readOnly": (
        "Space Read-Only",
        "Auto-created by saml_bulk_setup to mirror the legacy Member - Read Only space role.",
        [
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "SERVICE_KEY_READ",
        ],
    ),
    "annotator": (
        "Space Annotator",
        "Auto-created by saml_bulk_setup to mirror the legacy Annotator space role.",
        [
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "QUEUE_RECORD_ANNOTATE",
        ],
    ),
}


class RolesCache:
    """Resolve non-builtin space-role values to relay role IDs.

    Loaded once on first reference via paginated GET /v2/roles, which returns
    both predefined and custom roles for the authenticated account. Only
    consulted when the CSV value didn't match a builtin alias.
    """

    def __init__(
        self,
        api_key: str,
        logger: logging.Logger,
        arize_rest_api_url: str = ARIZE_REST_API_URL,
    ) -> None:
        self._api_key = api_key
        self._logger = logger
        self._rest_api_url = arize_rest_api_url.rstrip("/")
        self._name_to_id: dict[str, str] = {}
        self._role_ids: set[str] = set()
        self._loaded = False

    def id_to_name(self, role_id: str) -> str:
        """Return the human-readable name for a relay role ID, or the ID itself."""
        self._ensure_loaded()
        for name, rid in self._name_to_id.items():
            if rid == role_id:
                return name
        return role_id

    def resolve_custom_space_role(self, role_value: str) -> str:
        """Resolve a non-builtin space role name (or relay ID) to a relay role ID.

        Accepts either a role name (case-insensitive) or a relay global ID
        validated against the cache.
        """
        self._ensure_loaded()
        if role_value in self._role_ids:
            return role_value
        rid = self._name_to_id.get(role_value.lower())
        if rid:
            return rid
        available = ", ".join(sorted(self._name_to_id.keys())) or "(none)"
        raise ValueError(
            f"Custom role '{role_value}' not found in this account. "
            f"Available roles (case-insensitive): {available}"
        )

    def legacy_equivalent_id(self, legacy_role_key: str) -> str:
        """Return the relay ID for a legacy role's custom equivalent, if it exists.

        `legacy_role_key` is the GraphQL form: "admin" | "member" | "readOnly" |
        "annotator". Does not create the role — lookup only. Returns "" when the
        key is unknown or the equivalent custom role is not on the account yet.
        """
        if legacy_role_key not in LEGACY_ROLE_EQUIVALENTS:
            return ""
        self._ensure_loaded()
        equiv_name = LEGACY_ROLE_EQUIVALENTS[legacy_role_key][0].lower()
        return self._name_to_id.get(equiv_name, "")

    def ensure_legacy_equivalent_role(self, legacy_role_key: str) -> tuple[str, str]:
        """Get-or-create the custom role mirroring a legacy space role.

        `legacy_role_key` is the GraphQL form: "admin" | "member" | "readOnly" |
        "annotator". Returns (relay_role_id, custom_role_name). Idempotent: checks
        the cache first, POSTs if missing, recovers from a 409 race condition.
        """
        if legacy_role_key not in LEGACY_ROLE_EQUIVALENTS:
            raise ValueError(
                f"No legacy-equivalent permission set for '{legacy_role_key}'. "
                f"Known keys: {sorted(LEGACY_ROLE_EQUIVALENTS.keys())}"
            )
        name, description, permissions = LEGACY_ROLE_EQUIVALENTS[legacy_role_key]

        cached_id = self.legacy_equivalent_id(legacy_role_key)
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

        # 409 race: someone else just created the role — reload and look it up.
        self._loaded = False
        self._name_to_id.clear()
        self._role_ids.clear()
        self._ensure_loaded()
        racy_id = self._name_to_id.get(name.lower())
        if not racy_id:
            raise RuntimeError(
                f"POST /v2/roles for '{name}' returned 409 but the role wasn't "
                "visible after a cache reload. Re-run the script."
            )
        return racy_id, name

    def _post_role(
        self, name: str, description: str, permissions: list[str]
    ) -> str | None:
        """POST /v2/roles. Returns the new role's relay ID, or None on 409 Conflict."""
        url = f"{self._rest_api_url}/v2/roles"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        body = {"name": name, "description": description, "permissions": permissions}

        def post_role() -> requests.Response:
            r = requests.post(url, headers=headers, json=body, timeout=30)
            # 409 means the role already exists (race). Don't raise; caller handles it.
            if r.status_code == 409:
                return r
            r.raise_for_status()
            return r

        resp = with_retry(post_role, f"POST /v2/roles ({name})", self._logger)
        if resp.status_code == 409:
            return None
        payload = resp.json() or {}
        role = payload.get("role") if isinstance(payload.get("role"), dict) else payload
        rid = role.get("id") or ""
        if not rid:
            raise RuntimeError(f"POST /v2/roles for '{name}' returned no id: {payload}")
        return rid

    def _ensure_loaded(self) -> None:
        """Populate the role cache via paginated GET /v2/roles. Idempotent."""
        if self._loaded:
            return
        self._logger.debug("Loading account roles for custom-role lookup…")
        url = f"{self._rest_api_url}/v2/roles"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": 100}
            if cursor:
                params["cursor"] = cursor

            def fetch_page() -> requests.Response:
                r = requests.get(url, headers=headers, params=params, timeout=30)
                r.raise_for_status()
                return r

            resp = with_retry(fetch_page, "GET /v2/roles", self._logger)
            payload = resp.json()
            for role in payload.get("roles") or []:
                rid = role.get("id") or ""
                rname = role.get("name") or ""
                if rid and rname:
                    self._name_to_id[rname.lower()] = rid
                    self._role_ids.add(rid)
            pagination = payload.get("pagination") or {}
            if not pagination.get("has_more"):
                break
            cursor = pagination.get("next_cursor")
            if not cursor:
                break
        self._loaded = True
        self._logger.debug("  loaded %d account role(s)", len(self._name_to_id))
