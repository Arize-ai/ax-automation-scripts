#!/usr/bin/env python3
"""
arize_saml_bulk_setup.py — Bulk provision Arize organizations, spaces,
and SAML group role mappings from a CSV file.

Usage:
    python arize_saml_bulk_setup.py --csv ./saml_mappings.csv [--api-key KEY]
                                     [--dry-run] [--verbose] [--output results.csv]

Dependencies:
    pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

import requests
from arize_toolkit import Client as ArizeClient
from gql import gql

# ─── Constants ───────────────────────────────────────────────────────────────

ARIZE_APP_URL = "https://app.arize.com"
ARIZE_REST_API_URL = "https://api.arize.com"
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

# Base64 prefix for relay global IDs of the form "Role:<int>".
RELAY_ROLE_ID_PREFIX = "Um9sZTo"

# CSV accepts "viewer" as a human-friendly alias; Arize GraphQL uses "readOnly"
_ROLE_ALIAS: dict[str, str] = {
    "admin": "admin",
    "member": "member",
    "viewer": "readOnly",
    "annotator": "annotator",
}

VALID_ORG_ROLES: set[str] = set(
    _ROLE_ALIAS.keys()
)  # admin | member | viewer | annotator

OUTPUT_COLUMNS = [
    "organization",
    "space",
    "arize_org_role",
    "arize_space_role",
    "saml_attribute_name",
    "saml_attribute_value",
    "status",
    "error_message",
    "note",
]

# ─── Raw GraphQL — only for operations not in arize_toolkit ──────────────────

_CREATE_ORGANIZATION = gql("""
    mutation createOrganization($input: CreateOrganizationMutationInput!) {
        createOrganization(input: $input) {
            organization {
                id
                name
            }
        }
    }
""")

_CREATE_SAML_IDP = gql("""
    mutation createSAMLIdP($input: CreateSAMLIdPInput!) {
        createSAMLIdP(input: $input) {
            idp {
                id
                roleMappings {
                    id
                    attributesMap
                    spaceRolesMap
                    spaceRbacRolesMap
                    isAccountAdmin
                    orgRole {
                        orgId
                        roleId
                    }
                }
            }
            error
        }
    }
""")

_GET_SAML_IDP = gql("""
    query getSAMLIdP {
        account {
            samlIdPs(first: 1) {
                edges {
                    node {
                        id
                        emailDomainsList {
                            domain
                        }
                        enforceSaml
                        syncUserRoles
                        signAuthn
                        roleMappings {
                            id
                            attributesMap
                            spaceRolesMap
                            spaceRbacRolesMap
                            isAccountAdmin
                            orgRole {
                                orgId
                                roleId
                            }
                        }
                        allowLoginWithDefaults
                    }
                }
            }
        }
    }
""")

_UPDATE_SAML_IDP = gql("""
    mutation updateSAMLIdP($input: UpdateSAMLIdPInput!) {
        updateSAMLIdP(input: $input) {
            idp {
                id
                roleMappings {
                    id
                    attributesMap
                    spaceRolesMap
                    spaceRbacRolesMap
                }
            }
            error
        }
    }
""")


# ─── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class RowResult:
    row_number: int
    organization: str
    space: str
    arize_org_role: str
    arize_space_role: str
    saml_attribute_name: str
    saml_attribute_value: str
    status: str = ""
    error_message: str = ""
    note: str = ""


@dataclass
class PendingSAMLMapping:
    """A new SAML role mapping queued for creation, tied back to a CSV row."""

    row_number: int
    org_id: str
    space_id: str
    org_role: str  # translated: "admin" | "member" | "readOnly" | "annotator"
    # Exactly one of space_role / space_rbac_role_id is set (or both empty,
    # meaning inherit the space role from the org role).
    space_role: str  # legacy builtin: "admin" | "member" | "readOnly" | "annotator"
    space_rbac_role_id: str  # custom RBAC relay global ID (e.g. "Um9sZTo...")
    attr_name: str
    attr_value: str


@dataclass
class SamlFlags:
    """SAML config flags used for create defaults and update preservation."""

    enforce_saml: bool
    sync_user_roles: bool
    sign_authn: bool
    allow_login_with_defaults: bool


# ─── Retry helper ────────────────────────────────────────────────────────────

T = TypeVar("T")


def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "too many requests" in msg


def with_retry(
    fn: Callable[[], T],
    operation_name: str,
    logger: logging.Logger,
) -> T:
    """Call fn(), retrying with exponential backoff on rate-limit errors."""
    for attempt in range(MAX_RETRIES):
        try:
            return fn()
        except Exception as exc:
            if _is_rate_limit_error(exc) and attempt < MAX_RETRIES - 1:
                wait = INITIAL_BACKOFF * (2**attempt)
                logger.warning(
                    "Rate limit hit for '%s' (attempt %d/%d). Retrying in %.1fs…",
                    operation_name,
                    attempt + 1,
                    MAX_RETRIES,
                    wait,
                )
                time.sleep(wait)
            else:
                raise


# ─── Legacy role permission sets ─────────────────────────────────────────────
# Used to auto-create custom RBAC roles mirroring legacy space roles when a
# same-space conflict forces promotion. Keys are the GraphQL form after
# _ROLE_ALIAS translation: "admin" | "member" | "readOnly" | "annotator".
# Permission strings match proto/auth/protocol/permissions.proto.
# Source: go/pkg/lib/user/user.go lines 216-260 (as at 2026-05-15).

_LEGACY_ROLE_EQUIVALENTS: dict[str, tuple[str, str, list[str]]] = {
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


# ─── RolesCache ───────────────────────────────────────────────────────────────


class RolesCache:
    """Resolve non-builtin space-role values to relay role IDs.

    Loaded once on first reference via paginated GET /v2/roles, which returns
    both predefined and custom roles for the authenticated account. Only
    consulted when the CSV value didn't match a builtin alias.
    """

    def __init__(self, api_key: str, logger: logging.Logger) -> None:
        self._api_key = api_key
        self._logger = logger
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
        if role_value.startswith(RELAY_ROLE_ID_PREFIX) and role_value in self._role_ids:
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
        "annotator". Returns (relay_role_id, custom_role_name). Idempotent: checks
        the cache first, POSTs if missing, recovers from a 409 race condition.
        """
        if legacy_role_key not in _LEGACY_ROLE_EQUIVALENTS:
            raise ValueError(
                f"No legacy-equivalent permission set for '{legacy_role_key}'. "
                f"Known keys: {sorted(_LEGACY_ROLE_EQUIVALENTS.keys())}"
            )
        name, description, permissions = _LEGACY_ROLE_EQUIVALENTS[legacy_role_key]

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
        url = f"{ARIZE_REST_API_URL}/v2/roles"
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
        url = f"{ARIZE_REST_API_URL}/v2/roles"
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


# ─── Space-role classification ────────────────────────────────────────────────


def _classify_space_role(arize_space_role_raw: str) -> tuple[str, bool]:
    """Classify a CSV space-role cell.

    Returns (space_role, is_custom_space_role):
      - ""           → ("", False)  — inherit space role from org role
      - builtin alias → (translated, False) — legacy spaceRolesMap
      - anything else → ("", True)  — custom RBAC; resolved later to relay ID
    """
    if not arize_space_role_raw:
        return "", False
    lower = arize_space_role_raw.lower()
    if lower in _ROLE_ALIAS:
        return _ROLE_ALIAS[lower], False
    return "", True


# ─── Preflight: resolve same-space mixed-role-type conflicts ──────────────────


def _collect_space_role_uses(
    runner: "BulkSetupRunner",
) -> tuple[
    dict[str, list[tuple[int | None, str]]],
    dict[str, list[tuple[int | None, str]]],
]:
    """Return (legacy_uses, rbac_uses) dicts: space_id → [(row_or_None, label)].

    row_or_None is None for existing IdP entries not matched by any CSV row,
    or the CSV row number for pending/already_exists rows.
    """
    legacy_uses: dict[str, list[tuple[int | None, str]]] = {}
    rbac_uses: dict[str, list[tuple[int | None, str]]] = {}

    for mapping in runner.existing_mappings:
        for pair in mapping.get("spaceRolesMap") or []:
            if len(pair) >= 2 and pair[0]:
                legacy_uses.setdefault(pair[0], []).append((None, "standard"))
        for pair in mapping.get("spaceRbacRolesMap") or []:
            if len(pair) >= 2 and pair[0]:
                rbac_uses.setdefault(pair[0], []).append((None, "custom"))

    for p in runner.pending:
        if p.space_rbac_role_id:
            rbac_uses.setdefault(p.space_id, []).append((p.row_number, "custom"))
        elif p.space_role:
            legacy_uses.setdefault(p.space_id, []).append((p.row_number, "standard"))

    for row_number, space_id, space_role, space_rbac_role_id in runner.exact_match_uses:
        if space_rbac_role_id:
            rbac_uses.setdefault(space_id, []).append((row_number, "custom"))
        elif space_role:
            legacy_uses.setdefault(space_id, []).append((row_number, "standard"))

    return legacy_uses, rbac_uses


def _resolve_role_type_conflicts(
    runner: "BulkSetupRunner",
    results: list[RowResult],
    logger: logging.Logger,
    on_existed_to_error: Callable[[int], None],
    on_legacy_converted: Callable[[int, str, str, str], None],
) -> None:
    """Detect and auto-resolve same-space mixed-role-type conflicts.

    Arize enforces that every space uses either standard OR custom roles across
    all SAML mappings — never both. When the CSV would create a conflict on a
    space, this function promotes every legacy use on that space to a custom
    RBAC role mirroring its permission set. Custom is never demoted to legacy.

    Two shapes:
      - CSV-internal: two rows target the same space with mixed role types →
        pending legacy row(s) are converted to the legacy-equivalent custom role.
      - CSV-vs-existing: a CSV row touches a space where the IdP already holds
        the other role type → existing legacy entries are rewritten in place
        (spaceRolesMap → spaceRbacRolesMap), and already_exists rows get a note.

    Mutates `results` and `runner._saml_pending` / `runner._saml_existing_mappings`.
    Falls back to a row-level error if auto-promotion fails.
    """
    legacy_uses, rbac_uses = _collect_space_role_uses(runner)
    conflict_space_ids = set(legacy_uses) & set(rbac_uses)
    if not conflict_space_ids:
        return

    row_to_user_role = {r.row_number: r.arize_space_role for r in results}
    pending_row_numbers = runner.pending_row_numbers()
    row_errors: dict[int, str] = {}

    for space_id in conflict_space_ids:
        space_name = runner._space_id_to_name.get(space_id, "<unknown>")
        legacy_entries = legacy_uses[space_id]
        rbac_entries = rbac_uses[space_id]

        pending_legacy_rows = sorted(
            {
                row
                for row, _ in legacy_entries
                if row is not None and row in pending_row_numbers
            }
        )
        matched_legacy_rows = sorted(
            {
                row
                for row, _ in legacy_entries
                if row is not None and row not in pending_row_numbers
            }
        )
        pending_rbac_rows = sorted(
            {
                row
                for row, _ in rbac_entries
                if row is not None and row in pending_row_numbers
            }
        )
        matched_rbac_rows = sorted(
            {
                row
                for row, _ in rbac_entries
                if row is not None and row not in pending_row_numbers
            }
        )
        has_existing_legacy = any(row is None for row, _ in legacy_entries)

        try:
            # 1. Convert pending legacy rows to their custom equivalents.
            for row in pending_legacy_rows:
                outcome = runner.convert_legacy_to_custom(row, space_id)
                if outcome is None:
                    raise RuntimeError(
                        f"Row {row}: expected a pending legacy mapping for space "
                        f"'{space_name}' ({space_id}) but found none."
                    )
                legacy_key, custom_name = outcome
                on_legacy_converted(row, legacy_key, custom_name, "pending")
                logger.info(
                    "Row %d: auto-converted legacy '%s' → custom role '%s' (space '%s')",
                    row,
                    legacy_key,
                    custom_name,
                    space_name,
                )

            # 2. Promote pre-existing IdP legacy entries for this space.
            if has_existing_legacy:
                conversions = runner.promote_existing_legacy_for_space(space_id)
                for legacy_key, custom_name in conversions:
                    logger.info(
                        "Auto-promoted existing legacy '%s' → custom role '%s' on space '%s'",
                        legacy_key,
                        custom_name,
                        space_name,
                    )
                # Annotate matched (already_exists) rows whose entry was just promoted.
                if conversions and matched_legacy_rows:
                    rep_key, rep_name = conversions[0]
                    for row in matched_legacy_rows:
                        on_legacy_converted(row, rep_key, rep_name, "matched")

        except Exception:
            logger.exception(
                "Failed to auto-promote legacy roles for space '%s' (%s)",
                space_name,
                space_id,
            )

            def _describe(rows: list[int]) -> str:
                return (
                    ", ".join(
                        f"row {r} ('{row_to_user_role.get(r, '')}')" for r in rows
                    )
                    or "(none)"
                )

            message = (
                f"Space '{space_name}' would receive both a standard role and a custom role "
                f"across SAML mappings, which Arize does not allow. "
                f"Standard role in {_describe(pending_legacy_rows + matched_legacy_rows)}; "
                f"custom role in {_describe(pending_rbac_rows + matched_rbac_rows)}. "
                f"Auto-promotion failed — edit the CSV so this space uses one role type only."
            )
            for row in (
                pending_legacy_rows
                + pending_rbac_rows
                + matched_legacy_rows
                + matched_rbac_rows
            ):
                row_errors[row] = message

    if not row_errors:
        return

    for r in results:
        if r.row_number not in row_errors:
            continue
        if r.status == "already_exists":
            on_existed_to_error(r.row_number)
        r.status = "error"
        r.error_message = row_errors[r.row_number]
        logger.error("Row %d: %s", r.row_number, r.error_message)

    runner.drop_pending(set(row_errors.keys()))


# ─── Main runner ─────────────────────────────────────────────────────────────


class BulkSetupRunner:
    def __init__(
        self,
        api_key: str,
        dry_run: bool,
        verbose: bool,
        arize_app_url: str = ARIZE_APP_URL,
        saml_metadata_url: Optional[str] = None,
        saml_metadata_xml: Optional[str] = None,
        email_domains: Optional[list[str]] = None,
        enforce_saml: Optional[bool] = None,
        sync_user_roles: Optional[bool] = None,
        sign_authn: Optional[bool] = None,
    ) -> None:
        self.dry_run = dry_run

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.logger = logging.getLogger("arize_bulk_setup")
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.propagate = False

        self._api_key = api_key

        # arize_toolkit.Client handles auth and exposes get_all_organizations(),
        # get_all_spaces(), and create_new_space(). We initialise with no
        # org/space so it auto-resolves the first available one.
        self._toolkit = ArizeClient(
            arize_developer_key=api_key,
            arize_app_url=arize_app_url,
        )
        # _graphql_client is the underlying gql.Client
        self._gql = self._toolkit._graphql_client

        # Roles cache for custom RBAC role resolution
        self.roles = RolesCache(api_key=api_key, logger=self.logger)

        # In-memory caches
        self._org_cache: dict[str, str] = {}  # org_name → org_id
        self._org_cache_loaded = False
        self._space_cache: dict[
            tuple[str, str], str
        ] = {}  # (org_id, space_name) → space_id
        self._spaces_loaded_for: set[str] = set()  # org_ids already fetched
        self._space_id_to_name: dict[
            str, str
        ] = {}  # space_id → space_name (for conflict messages)

        # SAML IdP creation params (used if no IdP exists yet)
        self._saml_metadata_url = saml_metadata_url
        self._saml_metadata_xml = saml_metadata_xml
        self._email_domains = email_domains or []

        # SAML state — loaded once on first SAML operation
        self._saml_idp_id: Optional[str] = None
        self._saml_idp_needs_creation: bool = False  # True when no IdP found yet
        self._saml_existing_mappings: list[dict] = []
        self._saml_existing_email_domains: list[str] = []  # re-sent on updateSAMLIdP
        self._saml_pending: list[PendingSAMLMapping] = []
        # Rows that exactly matched an existing mapping (status=already_exists).
        # Each entry: (row_number, space_id, space_role, space_rbac_role_id).
        self._saml_exact_match_uses: list[tuple[int, str, str, str]] = []

        self._enforce_saml_override = enforce_saml is True
        self._sync_user_roles_override = sync_user_roles is True
        self._sign_authn_override = sign_authn is True
        self._saml_flags = SamlFlags(
            enforce_saml=bool(enforce_saml),
            sync_user_roles=True if sync_user_roles is None else sync_user_roles,
            sign_authn=bool(sign_authn),
            allow_login_with_defaults=False,
        )

        # Run counters
        self.orgs_created = 0
        self.orgs_existed = 0
        self.spaces_created = 0
        self.spaces_existed = 0
        self.mappings_created = 0
        self.mappings_existed = 0
        self.legacy_auto_conversions = 0
        self._counted_orgs: set[str] = set()
        self._counted_spaces: set[str] = set()

    # ── Duck-typed preflight protocol ─────────────────────────────────────────
    # These properties/methods are called by _resolve_role_type_conflicts().

    @property
    def existing_mappings(self) -> tuple[dict, ...]:
        return tuple(self._saml_existing_mappings)

    @property
    def pending(self) -> tuple[PendingSAMLMapping, ...]:
        return tuple(self._saml_pending)

    @property
    def exact_match_uses(self) -> tuple[tuple[int, str, str, str], ...]:
        return tuple(self._saml_exact_match_uses)

    def pending_row_numbers(self) -> set[int]:
        return {p.row_number for p in self._saml_pending}

    def drop_pending(self, row_numbers: set[int]) -> None:
        self._saml_pending = [
            p for p in self._saml_pending if p.row_number not in row_numbers
        ]

    def record_exact_match(
        self, row_number: int, space_id: str, space_role: str, space_rbac_role_id: str
    ) -> None:
        """Track a row that matched an existing mapping exactly (already_exists)."""
        if space_role or space_rbac_role_id:
            self._saml_exact_match_uses.append(
                (row_number, space_id, space_role, space_rbac_role_id)
            )

    def convert_legacy_to_custom(
        self, row_number: int, space_id: str
    ) -> tuple[str, str] | None:
        """Swap a pending legacy mapping to use a custom role in-place.

        Returns (legacy_key, new_custom_role_name), or None if no matching
        pending legacy mapping exists for this (row, space) pair.
        In dry-run mode resolves the name locally without POSTing to the API.
        """
        for p in self._saml_pending:
            if (
                p.row_number == row_number
                and p.space_id == space_id
                and p.space_role
                and not p.space_rbac_role_id
            ):
                legacy_key = p.space_role
                if self.dry_run:
                    custom_name = _LEGACY_ROLE_EQUIVALENTS[legacy_key][0]
                    p.space_rbac_role_id = f"__dry_run_role_{legacy_key}__"
                else:
                    p.space_rbac_role_id, custom_name = (
                        self.roles.ensure_legacy_equivalent_role(legacy_key)
                    )
                p.space_role = ""
                return legacy_key, custom_name
        return None

    def promote_existing_legacy_for_space(self, space_id: str) -> list[tuple[str, str]]:
        """Rewrite spaceRolesMap → spaceRbacRolesMap for space_id in existing mappings.

        Returns a deduped list of (legacy_key, custom_name) for each unique conversion.
        Idempotent: entries already in spaceRbacRolesMap are not duplicated.
        In dry-run mode resolves names locally without POSTing to the API.
        """
        conversions: dict[str, str] = {}
        for mapping in self._saml_existing_mappings:
            legacy_entries: list[list[str]] = mapping.get("spaceRolesMap") or []
            if not legacy_entries:
                continue
            kept: list[list[str]] = []
            for pair in legacy_entries:
                if len(pair) < 2 or pair[0] != space_id:
                    kept.append(pair)
                    continue
                legacy_key = pair[1]
                if self.dry_run:
                    custom_name = _LEGACY_ROLE_EQUIVALENTS[legacy_key][0]
                    relay_id = f"__dry_run_role_{legacy_key}__"
                else:
                    relay_id, custom_name = self.roles.ensure_legacy_equivalent_role(
                        legacy_key
                    )
                conversions[legacy_key] = custom_name
                rbac_entries: list[list[str]] = (
                    mapping.setdefault("spaceRbacRolesMap", []) or []
                )
                if not any(
                    len(e) >= 2 and e[0] == space_id and e[1] == relay_id
                    for e in rbac_entries
                ):
                    rbac_entries.append([space_id, relay_id])
                mapping["spaceRbacRolesMap"] = rbac_entries
            mapping["spaceRolesMap"] = kept
        return list(conversions.items())

    # ── Org context management ────────────────────────────────────────────────

    def _set_toolkit_org(self, org_id: str, org_name: str) -> None:
        """Point the toolkit client at a specific org without an extra API call.

        get_all_spaces() and create_new_space() both use self._toolkit.org_id
        internally, so we update it directly before calling them.
        """
        self._toolkit.org_id = org_id
        self._toolkit.organization = org_name

    # ── Organization helpers ──────────────────────────────────────────────────

    def _load_all_organizations(self) -> None:
        if self._org_cache_loaded:
            return
        self.logger.debug("Loading all organizations…")
        orgs = with_retry(
            lambda: self._toolkit.get_all_organizations(),
            "get_all_organizations",
            self.logger,
        )
        for org in orgs:
            self._org_cache[org["name"]] = org["id"]
            self.logger.debug("  org: %s (%s)", org["name"], org["id"])
        self._org_cache_loaded = True

    def _resolve_org(self, org_name: str) -> tuple[str, str]:
        """Return (org_id, status). Creates the org if it doesn't exist."""
        self._load_all_organizations()

        if org_name in self._org_cache:
            org_id = self._org_cache[org_name]
            self._set_toolkit_org(org_id, org_name)
            return org_id, "already_exists"

        self.logger.info("Creating organization: %s", org_name)
        if self.dry_run:
            fake_id = f"__dry_run_org_{org_name}__"
            self._org_cache[org_name] = fake_id
            self._set_toolkit_org(fake_id, org_name)
            self.logger.info("[DRY RUN] Would create organization: %s", org_name)
            return fake_id, "dry_run"

        result = with_retry(
            lambda: self._gql.execute(
                _CREATE_ORGANIZATION,
                variable_values={"input": {"name": org_name}},
            ),
            "createOrganization",
            self.logger,
        )
        org = result["createOrganization"]["organization"]
        self._org_cache[org["name"]] = org["id"]
        self._set_toolkit_org(org["id"], org["name"])
        return org["id"], "created"

    # ── Space helpers ─────────────────────────────────────────────────────────

    def _load_spaces_for_org(self, org_id: str, org_name: str) -> None:
        if org_id in self._spaces_loaded_for:
            return
        if org_id.startswith("__dry_run_"):
            # Org only exists as a dry-run placeholder — no real ID to query
            self._spaces_loaded_for.add(org_id)
            return
        self.logger.debug("Loading spaces for org '%s'…", org_name)
        self._set_toolkit_org(org_id, org_name)
        spaces = with_retry(
            lambda: self._toolkit.get_all_spaces(),
            "get_all_spaces",
            self.logger,
        )
        for space in spaces:
            self._space_cache[(org_id, space["name"])] = space["id"]
            self._space_id_to_name[space["id"]] = space["name"]
            self.logger.debug("  space: %s (%s)", space["name"], space["id"])
        self._spaces_loaded_for.add(org_id)

    def _resolve_space(
        self, org_id: str, org_name: str, space_name: str
    ) -> tuple[str, str]:
        """Return (space_id, status). Creates the space if it doesn't exist."""
        self._load_spaces_for_org(org_id, org_name)

        cache_key = (org_id, space_name)
        if cache_key in self._space_cache:
            return self._space_cache[cache_key], "already_exists"

        self.logger.info("Creating space '%s' in org '%s'…", space_name, org_name)
        if self.dry_run:
            fake_id = f"__dry_run_space_{space_name}__"
            self._space_cache[cache_key] = fake_id
            self._space_id_to_name[fake_id] = space_name
            self.logger.info("[DRY RUN] Would create space: %s", space_name)
            return fake_id, "dry_run"

        self._set_toolkit_org(org_id, org_name)
        new_space_id = with_retry(
            # set_as_active=False — we manage org context ourselves; no need
            # to trigger the extra switch_space() call inside the toolkit.
            lambda: self._toolkit.create_new_space(
                name=space_name, private=True, set_as_active=False
            ),
            "create_new_space",
            self.logger,
        )
        self._space_cache[cache_key] = new_space_id
        self._space_id_to_name[new_space_id] = space_name
        return new_space_id, "created"

    # ── SAML helpers ──────────────────────────────────────────────────────────

    def _load_saml_idp(self) -> None:
        """Check for an existing SAMLIdP and load its role mappings (once).

        If no IdP exists, sets _saml_idp_needs_creation=True and returns
        without raising — creation is deferred to _flush_saml_mappings() so
        all pending mappings can be included in a single createSAMLIdP call
        (the API requires at least one mapping when allowLoginWithDefaults=False).
        """
        if self._saml_idp_id is not None or self._saml_idp_needs_creation:
            return
        self.logger.debug("Loading SAML IdP…")
        result = with_retry(
            lambda: self._gql.execute(_GET_SAML_IDP, variable_values={}),
            "getSAMLIdP",
            self.logger,
        )
        edges = result["account"]["samlIdPs"]["edges"]
        if not edges:
            self._validate_saml_creation_params()
            self._saml_idp_needs_creation = True
            self.logger.info(
                "No SAMLIdP found — will create one with all collected mappings."
            )
            return
        idp = edges[0]["node"]
        self._saml_idp_id = idp["id"]
        self._saml_existing_mappings = idp.get("roleMappings") or []
        self._saml_existing_email_domains = [
            d["domain"] for d in (idp.get("emailDomainsList") or [])
        ]
        self._saml_flags = SamlFlags(
            enforce_saml=idp.get("enforceSaml") or False,
            sync_user_roles=idp.get("syncUserRoles") or False,
            sign_authn=idp.get("signAuthn") or False,
            allow_login_with_defaults=idp.get("allowLoginWithDefaults") or False,
        )
        if self._enforce_saml_override:
            self._saml_flags.enforce_saml = True
        if self._sync_user_roles_override:
            self._saml_flags.sync_user_roles = True
        if self._sign_authn_override:
            self._saml_flags.sign_authn = True
        self.logger.debug(
            "Found SAMLIdP %s with %d existing role mapping(s)",
            self._saml_idp_id,
            len(self._saml_existing_mappings),
        )

    def _validate_saml_creation_params(self) -> None:
        """Raise early if the params needed to create a new IdP are missing."""
        if not self._email_domains:
            raise RuntimeError(
                "No SAML IdP found for this account. "
                "Provide --email-domains and either --saml-metadata-url or "
                "--saml-metadata-xml to create one automatically, or configure "
                "SAML in the Arize UI first."
            )
        if not self._saml_metadata_url and not self._saml_metadata_xml:
            raise RuntimeError(
                "No SAML IdP found and no metadata supplied. "
                "Provide --saml-metadata-url or --saml-metadata-xml to create one."
            )

    def _create_saml_idp_with_mappings(self, mappings_input: list[dict]) -> None:
        """Create a new SAMLIdP and include all pending mappings in one call."""
        if self.dry_run:
            self.logger.info(
                "[DRY RUN] Would create SAMLIdP (metadata_url=%s, domains=%s) "
                "with %d mapping(s)",
                self._saml_metadata_url,
                self._email_domains,
                len(mappings_input),
            )
            self._saml_idp_id = "__dry_run_saml_idp__"
            return

        self.logger.info(
            "Creating SAMLIdP (domains: %s) with %d mapping(s)…",
            ", ".join(self._email_domains),
            len(mappings_input),
        )
        idp_input: dict = {
            "emailDomainsList": [{"domain": d} for d in self._email_domains],
            "enforceSaml": self._saml_flags.enforce_saml,
            "syncUserRoles": self._saml_flags.sync_user_roles,
            "signAuthn": self._saml_flags.sign_authn,
            "allowLoginWithDefaults": self._saml_flags.allow_login_with_defaults,
            "roleMappings": {"mappingsList": mappings_input},
        }
        if self._saml_metadata_url:
            idp_input["metadataUrl"] = self._saml_metadata_url
        if self._saml_metadata_xml:
            idp_input["metadataXml"] = self._saml_metadata_xml

        result = with_retry(
            lambda: self._gql.execute(
                _CREATE_SAML_IDP, variable_values={"input": idp_input}
            ),
            "createSAMLIdP",
            self.logger,
        )
        payload = result.get("createSAMLIdP", {})
        if payload.get("error"):
            raise RuntimeError(f"createSAMLIdP returned error: {payload['error']}")
        idp = payload["idp"]
        self._saml_idp_id = idp["id"]
        self._saml_existing_mappings = idp.get("roleMappings") or []
        self.logger.info("SAMLIdP created: %s", self._saml_idp_id)

    def _mapping_exists(
        self,
        space_id: str,
        org_role: str,
        space_role: str,
        space_rbac_role_id: str,
        attr_name: str,
        attr_value: str,
    ) -> bool:
        """True if any existing or already-queued mapping covers this combo.

        Handles all three space-role shapes:
          - inherited  (both space_role and space_rbac_role_id empty)
          - legacy builtin (space_role set)
          - custom RBAC (space_rbac_role_id set)
        """
        for mapping in self._saml_existing_mappings:
            attrs = mapping.get("attributesMap") or []
            legacy_spaces = mapping.get("spaceRolesMap") or []
            rbac_spaces = mapping.get("spaceRbacRolesMap") or []
            existing_org_role = (mapping.get("orgRole") or {}).get("roleId", "")
            has_attr = any(
                len(p) >= 2 and p[0] == attr_name and p[1] == attr_value for p in attrs
            )
            if not has_attr or existing_org_role != org_role:
                continue
            # Inherited — attr + org role is the full identity
            if not space_role and not space_rbac_role_id:
                return True
            if space_rbac_role_id and any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_rbac_role_id
                for p in rbac_spaces
            ):
                return True
            if space_role and any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_role
                for p in legacy_spaces
            ):
                return True
            # A prior run may have promoted this legacy role to its custom equivalent
            # (spaceRolesMap → spaceRbacRolesMap). Check for that relay ID so re-runs
            # correctly report already_exists instead of creating a duplicate.
            if (
                space_role
                and not space_rbac_role_id
                and space_role in _LEGACY_ROLE_EQUIVALENTS
                and rbac_spaces
            ):
                self.roles._ensure_loaded()
                equiv_name = _LEGACY_ROLE_EQUIVALENTS[space_role][0].lower()
                equiv_id = self.roles._name_to_id.get(equiv_name, "")
                if equiv_id and any(
                    len(p) >= 2 and p[0] == space_id and p[1] == equiv_id
                    for p in rbac_spaces
                ):
                    return True
        # Also deduplicate within the current run
        return any(
            p.attr_name == attr_name
            and p.attr_value == attr_value
            and p.org_role == org_role
            and (
                (not space_role and not space_rbac_role_id)
                or (
                    space_rbac_role_id
                    and p.space_id == space_id
                    and p.space_rbac_role_id == space_rbac_role_id
                )
                or (
                    space_role and p.space_id == space_id and p.space_role == space_role
                )
            )
            for p in self._saml_pending
        )

    def _build_new_mappings_input(self) -> list[dict]:
        entries = []
        for p in self._saml_pending:
            entry: dict = {
                "attributesMap": [[p.attr_name, p.attr_value]],
                "orgRole": {"orgId": p.org_id, "roleId": p.org_role},
                "isAccountAdmin": False,
            }
            # Custom RBAC role → spaceRbacRolesMap; legacy builtin → spaceRolesMap;
            # neither → inherited from org role (omit both maps).
            if p.space_rbac_role_id:
                entry["spaceRbacRolesMap"] = [[p.space_id, p.space_rbac_role_id]]
            elif p.space_role:
                entry["spaceRolesMap"] = [[p.space_id, p.space_role]]
            entries.append(entry)
        return entries

    def _flush_saml_mappings(self) -> None:
        """Persist all pending mappings in a single API call.

        - If the IdP already existed: updateSAMLIdP (full-replace, existing + new).
        - If no IdP existed yet: createSAMLIdP with all mappings included
          (the API requires at least one mapping when allowLoginWithDefaults=False).
        """
        if not self._saml_pending:
            return

        new_mappings = self._build_new_mappings_input()

        if self._saml_idp_needs_creation:
            self._create_saml_idp_with_mappings(new_mappings)
            return

        if self._saml_idp_id is None:
            return

        # Re-serialize existing mappings, preserving both role map types.
        # Preflight may have mutated spaceRolesMap/spaceRbacRolesMap in place
        # (promote_existing_legacy_for_space), so we use the current in-memory state.
        mappings_input = []
        for m in self._saml_existing_mappings:
            entry: dict = {
                "attributesMap": m.get("attributesMap") or [],
                "spaceRolesMap": m.get("spaceRolesMap") or [],
                "spaceRbacRolesMap": m.get("spaceRbacRolesMap") or [],
                "isAccountAdmin": m.get("isAccountAdmin") or False,
            }
            if m.get("id"):
                entry["id"] = m["id"]
            if m.get("orgRole"):
                entry["orgRole"] = {
                    "orgId": m["orgRole"]["orgId"],
                    "roleId": m["orgRole"]["roleId"],
                }
            mappings_input.append(entry)
        mappings_input.extend(new_mappings)

        self.logger.info(
            "Updating SAMLIdP (raw GQL): %d existing + %d new mapping(s)",
            len(self._saml_existing_mappings),
            len(self._saml_pending),
        )
        # Re-include the existing email domains — updateSAMLIdP requires at least one
        email_domains_for_update = (
            self._email_domains or self._saml_existing_email_domains
        )
        update_input: dict = {
            "id": self._saml_idp_id,
            "roleMappings": {"mappingsList": mappings_input},
            "emailDomainsList": [{"domain": d} for d in email_domains_for_update],
        }
        if self._saml_flags:
            update_input.update(
                {
                    "enforceSaml": self._saml_flags.enforce_saml,
                    "syncUserRoles": self._saml_flags.sync_user_roles,
                    "signAuthn": self._saml_flags.sign_authn,
                    "allowLoginWithDefaults": self._saml_flags.allow_login_with_defaults,
                }
            )
        result = with_retry(
            lambda: self._gql.execute(
                _UPDATE_SAML_IDP,
                variable_values={"input": update_input},
            ),
            "updateSAMLIdP",
            self.logger,
        )
        if result and result.get("updateSAMLIdP", {}).get("error"):
            raise RuntimeError(
                f"updateSAMLIdP returned error: {result['updateSAMLIdP']['error']}"
            )

    # ── Row processor ─────────────────────────────────────────────────────────

    def process_row(self, row: dict, row_number: int) -> RowResult:
        org_name = (row.get("organization") or "").strip()
        space_name = (row.get("space") or "").strip()
        arize_org_role = (row.get("arize_org_role") or "").strip().lower()
        # Preserve case: custom role names are case-insensitive for lookup but
        # we keep the raw value for error messages and the results CSV.
        arize_space_role_raw = (row.get("arize_space_role") or "").strip()
        attr_name = (row.get("saml_attribute_name") or "").strip()
        attr_value = (row.get("saml_attribute_value") or "").strip()

        result = RowResult(
            row_number=row_number,
            organization=org_name,
            space=space_name,
            arize_org_role=arize_org_role,
            arize_space_role=arize_space_role_raw,
            saml_attribute_name=attr_name,
            saml_attribute_value=attr_value,
        )

        # Validate required fields are non-empty
        missing = [
            col
            for col, val in [
                ("organization", org_name),
                ("space", space_name),
                ("arize_org_role", arize_org_role),
                ("saml_attribute_name", attr_name),
                ("saml_attribute_value", attr_value),
            ]
            if not val
        ]
        if missing:
            result.status = "error"
            result.error_message = f"Missing required field(s): {', '.join(missing)}"
            return result

        # ── Role validation ────────────────────────────────────────────────────
        if arize_org_role not in VALID_ORG_ROLES:
            result.status = "error"
            result.error_message = (
                f"Invalid arize_org_role '{arize_org_role}'. "
                f"Must be one of: {', '.join(sorted(VALID_ORG_ROLES))}"
            )
            return result

        if arize_org_role == "admin":
            # Org admin gets full org access — a space role is not applicable
            if arize_space_role_raw:
                result.status = "error"
                result.error_message = (
                    f"Invalid combination: arize_org_role='admin' cannot be paired "
                    f"with arize_space_role='{arize_space_role_raw}'. "
                    "Org admins receive full org access; leave arize_space_role blank."
                )
                return result

        # Classify space role: builtin alias, custom name, or empty (inherit).
        # Note: no hard validation for custom names here — the roles cache check
        # below provides the authoritative error if the name doesn't exist.
        space_role, is_custom_space_role = _classify_space_role(arize_space_role_raw)
        org_role = _ROLE_ALIAS[arize_org_role]

        try:
            # 1. Resolve org (arize_toolkit: get_all_organizations / raw GQL: createOrganization)
            org_id, org_status = self._resolve_org(org_name)
            if org_id not in self._counted_orgs:
                self._counted_orgs.add(org_id)
                if org_status in ("created", "dry_run"):
                    self.orgs_created += 1
                elif org_status == "already_exists":
                    self.orgs_existed += 1
            self.logger.debug(
                "Row %d: org '%s' — %s (%s)", row_number, org_name, org_status, org_id
            )

            # 2. Resolve space (arize_toolkit: get_all_spaces / create_new_space)
            space_id, space_status = self._resolve_space(org_id, org_name, space_name)
            if space_id not in self._counted_spaces:
                self._counted_spaces.add(space_id)
                if space_status in ("created", "dry_run"):
                    self.spaces_created += 1
                elif space_status == "already_exists":
                    self.spaces_existed += 1
            self.logger.debug(
                "Row %d: space '%s' — %s (%s)",
                row_number,
                space_name,
                space_status,
                space_id,
            )

            # 3. SAML mapping
            self._load_saml_idp()

            # Resolve custom RBAC role to relay ID (only for non-builtin roles)
            space_rbac_role_id = ""
            if is_custom_space_role:
                try:
                    space_rbac_role_id = self.roles.resolve_custom_space_role(
                        arize_space_role_raw
                    )
                except ValueError as exc:
                    if not self.dry_run:
                        raise
                    # Dry-run: warn but don't fail. Skip queuing the mapping
                    # since we don't have a relay ID.
                    self.logger.warning("Row %d: %s", row_number, exc)
                    result.status = "dry_run"
                    result.note = (
                        f"Custom role '{arize_space_role_raw}' does not exist on "
                        "this account — this row would fail in a real run. "
                        "Create the role in the Arize UI or fix the CSV name, "
                        "then rerun."
                    )
                    return result

            if self._mapping_exists(
                space_id,
                org_role,
                space_role,
                space_rbac_role_id,
                attr_name,
                attr_value,
            ):
                self.mappings_existed += 1
                result.status = "already_exists"
                self.record_exact_match(
                    row_number, space_id, space_role, space_rbac_role_id
                )
                self.logger.debug(
                    "Row %d: SAML mapping (%s=%s → %s, org:%s/space:%s) already exists — skipping",
                    row_number,
                    attr_name,
                    attr_value,
                    space_name,
                    arize_org_role,
                    arize_space_role_raw or "n/a",
                )
            else:
                if self.dry_run:
                    self.logger.info(
                        "[DRY RUN] Row %d: Would create SAML mapping (%s=%s → %s, org:%s/space:%s)",
                        row_number,
                        attr_name,
                        attr_value,
                        space_name,
                        arize_org_role,
                        arize_space_role_raw or "n/a",
                    )
                    result.status = "dry_run"
                else:
                    result.status = "created"
                    self.logger.debug(
                        "Row %d: SAML mapping (%s=%s → %s, org:%s/space:%s) queued",
                        row_number,
                        attr_name,
                        attr_value,
                        space_name,
                        arize_org_role,
                        arize_space_role_raw or "n/a",
                    )
                self._saml_pending.append(
                    PendingSAMLMapping(
                        row_number=row_number,
                        org_id=org_id,
                        space_id=space_id,
                        org_role=org_role,
                        space_role=space_role,
                        space_rbac_role_id=space_rbac_role_id,
                        attr_name=attr_name,
                        attr_value=attr_value,
                    )
                )

        except Exception as exc:
            result.status = "error"
            result.error_message = str(exc)
            self.logger.error("Row %d failed: %s", row_number, exc)

        return result

    # ── Top-level run ─────────────────────────────────────────────────────────

    def run(self, rows: list[dict]) -> list[RowResult]:
        results: list[RowResult] = []

        for i, row in enumerate(rows, start=1):
            results.append(self.process_row(row, i))

        # Preflight: resolve same-space legacy vs custom role conflicts before flush.
        # When a space would get both standard and custom role mappings (Arize
        # rejects this), auto-promote all legacy uses on that space to their
        # custom-role equivalents. Mutates results, _saml_pending, and
        # _saml_existing_mappings in place.
        results_by_row = {r.row_number: r for r in results}

        def _on_legacy_converted(
            row_number: int, legacy_key: str, custom_name: str, kind: str
        ) -> None:
            self.legacy_auto_conversions += 1
            r = results_by_row.get(row_number)
            if r is None:
                return
            if kind == "matched":
                r.note = (
                    f"Existing legacy mapping was auto-promoted to custom role "
                    f"'{custom_name}' because another mapping on this space "
                    "uses a custom role."
                )
            else:
                r.note = (
                    f"Auto-converted legacy '{legacy_key}' to custom role "
                    f"'{custom_name}' because this space also uses a custom role "
                    "in another mapping."
                )

        def _on_existed_to_error(row_number: int) -> None:
            self.mappings_existed -= 1

        _resolve_role_type_conflicts(
            runner=self,
            results=results,
            logger=self.logger,
            on_existed_to_error=_on_existed_to_error,
            on_legacy_converted=_on_legacy_converted,
        )

        if self.dry_run:
            self.mappings_created = len(self._saml_pending)

        # Flush all queued SAML mappings in a single updateSAMLIdP call
        if self._saml_pending and not self.dry_run:
            try:
                self._flush_saml_mappings()
                self.mappings_created += len(self._saml_pending)
                self.logger.info(
                    "%d new SAML mapping(s) created.", len(self._saml_pending)
                )
            except Exception as exc:
                self.logger.error("Failed to flush SAML mappings: %s", exc)
                pending_rows = {p.row_number for p in self._saml_pending}
                for r in results:
                    if r.row_number in pending_rows and r.status == "created":
                        r.status = "error"
                        r.error_message = f"SAML update failed: {exc}"
        return results


# ─── CSV helpers ─────────────────────────────────────────────────────────────

REQUIRED_COLUMNS = {
    "organization",
    "space",
    "arize_org_role",
    "arize_space_role",
    "saml_attribute_name",
    "saml_attribute_value",
}


def load_csv(path: str) -> list[dict]:
    if not os.path.isfile(path):
        print(f"ERROR: CSV file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            print("ERROR: CSV file is empty.", file=sys.stderr)
            sys.exit(1)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            print(
                f"ERROR: CSV is missing required columns: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            sys.exit(1)
        rows = [row for row in reader if any(v and v.strip() for v in row.values())]
    if not rows:
        print("ERROR: CSV file has no data rows.", file=sys.stderr)
        sys.exit(1)
    return rows


def write_results_csv(results: list[RowResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "organization": r.organization,
                    "space": r.space,
                    "arize_org_role": r.arize_org_role,
                    "arize_space_role": r.arize_space_role,
                    "saml_attribute_name": r.saml_attribute_name,
                    "saml_attribute_value": r.saml_attribute_value,
                    "status": r.status,
                    "error_message": r.error_message,
                    "note": r.note,
                }
            )


# ─── Summary printer ─────────────────────────────────────────────────────────


def print_summary(
    runner: BulkSetupRunner, results: list[RowResult], output_path: str
) -> None:
    errors = [r for r in results if r.status == "error"]
    print()
    print("─" * 50)
    print("Summary")
    print("─" * 50)
    print(
        f"  Organizations : {runner.orgs_created} created, {runner.orgs_existed} already existed"
    )
    print(
        f"  Spaces        : {runner.spaces_created} created, {runner.spaces_existed} already existed"
    )
    print(
        f"  SAML mappings : {runner.mappings_created} created, {runner.mappings_existed} already existed"
    )
    if runner.legacy_auto_conversions:
        print(
            f"  Auto-promoted : {runner.legacy_auto_conversions} legacy role(s) converted to custom"
        )
    if errors:
        print(f"  Errors        : {len(errors)} row(s) failed — review {output_path}")
    else:
        print("  Errors        : 0")
    print("─" * 50)
    if errors:
        print(f"\n{len(errors)} row(s) failed. See '{output_path}' for details.")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arize_saml_bulk_setup.py",
        description=(
            "Bulk provision Arize organizations, spaces, and SAML group "
            "role mappings from a CSV file."
        ),
    )
    parser.add_argument(
        "--csv", required=True, metavar="CSV", help="Path to input CSV file"
    )
    parser.add_argument(
        "--api-key",
        metavar="API_KEY",
        help="Arize API key (or set ARIZE_API_KEY / ARIZE_DEVELOPER_KEY env var)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview actions without API calls"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable per-row debug logging"
    )
    parser.add_argument(
        "--output",
        default="saml_setup_results.csv",
        metavar="OUTPUT",
        help="Path for results CSV (default: saml_setup_results.csv)",
    )
    parser.add_argument(
        "--arize-url",
        default=ARIZE_APP_URL,
        metavar="URL",
        help=f"Arize app base URL (default: {ARIZE_APP_URL})",
    )

    saml_group = parser.add_argument_group(
        "SAML IdP creation (only needed if no IdP is configured yet)"
    )
    saml_group.add_argument(
        "--saml-metadata-url",
        metavar="URL",
        help="URL to fetch SAML IdP metadata from (mutually exclusive with --saml-metadata-xml)",
    )
    saml_group.add_argument(
        "--saml-metadata-xml",
        metavar="XML",
        help="Raw SAML IdP metadata XML string (mutually exclusive with --saml-metadata-url)",
    )
    saml_group.add_argument(
        "--email-domains",
        metavar="DOMAINS",
        help="Comma-separated email domains for the IdP (e.g. acme.com,subsidiary.com)",
    )
    saml_group.add_argument(
        "--enforce-saml",
        action="store_true",
        default=None,
        help="Enable SAML enforcement on create, or turn it on for an existing IdP update",
    )
    saml_group.add_argument(
        "--sync-user-roles",
        action="store_true",
        default=None,
        help="Enable sync user roles on create, or turn it on for an existing IdP update",
    )
    saml_group.add_argument(
        "--sign-authn",
        action="store_true",
        default=None,
        help="Enable signed authn requests on create, or turn it on for an existing IdP update",
    )
    return parser


def resolve_api_key(cli_key: Optional[str]) -> str:
    key = (
        cli_key
        or os.environ.get("ARIZE_API_KEY")
        or os.environ.get("ARIZE_DEVELOPER_KEY")
    )
    if not key:
        print(
            "ERROR: No API key provided. Use --api-key or set ARIZE_API_KEY.",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.saml_metadata_url and args.saml_metadata_xml:
        parser.error(
            "--saml-metadata-url and --saml-metadata-xml are mutually exclusive."
        )

    api_key = resolve_api_key(args.api_key)
    rows = load_csv(args.csv)

    if args.dry_run:
        print("DRY RUN — no changes will be made.\n")

    email_domains = (
        [d.strip() for d in args.email_domains.split(",") if d.strip()]
        if args.email_domains
        else None
    )

    runner = BulkSetupRunner(
        api_key=api_key,
        dry_run=args.dry_run,
        verbose=args.verbose,
        arize_app_url=args.arize_url,
        saml_metadata_url=args.saml_metadata_url,
        saml_metadata_xml=args.saml_metadata_xml,
        email_domains=email_domains,
        enforce_saml=args.enforce_saml,
        sync_user_roles=args.sync_user_roles,
        sign_authn=args.sign_authn,
    )

    results = runner.run(rows)

    write_results_csv(results, args.output)
    print_summary(runner, results, args.output)

    sys.exit(1 if any(r.status == "error" for r in results) else 0)


if __name__ == "__main__":
    main()
