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
from typing import Callable, Optional, TypeVar

from arize_toolkit import Client as ArizeClient
from gql import gql

# ─── Constants ───────────────────────────────────────────────────────────────

ARIZE_APP_URL = "https://app.arize.com"
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

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
VALID_SPACE_ROLES: set[str] = set(
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


@dataclass
class PendingSAMLMapping:
    """A new SAML role mapping queued for creation, tied back to a CSV row."""

    row_number: int
    org_id: str
    space_id: str
    org_role: str  # translated: "admin" | "member" | "readOnly" | "annotator"
    space_role: str  # translated: "admin" | "member" | "readOnly" | "annotator"
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

        # arize_toolkit.Client handles auth and exposes get_all_organizations(),
        # get_all_spaces(), and create_new_space(). We initialise with no
        # org/space so it auto-resolves the first available one.
        self._toolkit = ArizeClient(
            arize_developer_key=api_key,
            arize_app_url=arize_app_url,
        )
        # _graphql_client is the underlying gql.Client
        self._gql = self._toolkit._graphql_client

        # In-memory caches
        self._org_cache: dict[str, str] = {}  # org_name → org_id
        self._org_cache_loaded = False
        self._space_cache: dict[
            tuple[str, str], str
        ] = {}  # (org_id, space_name) → space_id
        self._spaces_loaded_for: set[str] = set()  # org_ids already fetched

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
        self._counted_orgs: set[str] = set()
        self._counted_spaces: set[str] = set()

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
        attr_name: str,
        attr_value: str,
    ) -> bool:
        """True if any existing or already-queued mapping covers this combo.

        When the IdP doesn't exist yet (_saml_idp_needs_creation=True) there
        are no existing mappings, so only the within-run dedup check applies.
        """
        for mapping in self._saml_existing_mappings:
            attrs = mapping.get("attributesMap") or []
            spaces = mapping.get("spaceRolesMap") or []
            existing_org_role = (mapping.get("orgRole") or {}).get("roleId", "")
            has_attr = any(
                len(p) >= 2 and p[0] == attr_name and p[1] == attr_value for p in attrs
            )
            if not has_attr or existing_org_role != org_role:
                continue
            # No space role — attr + org role is the full identity
            if not space_role:
                return True
            # Space role specified — verify it's present in spaceRolesMap
            if any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_role for p in spaces
            ):
                return True
        # Also deduplicate within the current run
        return any(
            p.attr_name == attr_name
            and p.attr_value == attr_value
            and p.org_role == org_role
            and (
                not space_role
                or (p.space_id == space_id and p.space_role == space_role)
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
            # Include space role only when explicitly set — omitting it lets the
            # backend inherit the space role from the org role.
            if p.space_role:
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

        # Re-serialize existing mappings preserving their IDs
        mappings_input = []
        for m in self._saml_existing_mappings:
            entry: dict = {
                "attributesMap": m.get("attributesMap") or [],
                "spaceRolesMap": m.get("spaceRolesMap") or [],
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
            update_input.update({
                "enforceSaml": self._saml_flags.enforce_saml,
                "syncUserRoles": self._saml_flags.sync_user_roles,
                "signAuthn": self._saml_flags.sign_authn,
                "allowLoginWithDefaults": self._saml_flags.allow_login_with_defaults,
            })
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
        arize_space_role = (row.get("arize_space_role") or "").strip().lower()
        attr_name = (row.get("saml_attribute_name") or "").strip()
        attr_value = (row.get("saml_attribute_value") or "").strip()

        result = RowResult(
            row_number=row_number,
            organization=org_name,
            space=space_name,
            arize_org_role=arize_org_role,
            arize_space_role=arize_space_role,
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
            if arize_space_role:
                result.status = "error"
                result.error_message = (
                    f"Invalid combination: arize_org_role='admin' cannot be paired "
                    f"with arize_space_role='{arize_space_role}'. "
                    "Org admins receive full org access; leave arize_space_role blank."
                )
                return result
        else:
            # Space role is optional for non-admin org roles — when omitted the
            # backend inherits the space role from the org role.
            # If a value IS provided it must be a recognised role name.
            if arize_space_role and arize_space_role not in VALID_SPACE_ROLES:
                result.status = "error"
                result.error_message = (
                    f"Invalid arize_space_role '{arize_space_role}'. "
                    f"Must be one of: {', '.join(sorted(VALID_SPACE_ROLES))}, "
                    "or leave blank to inherit from arize_org_role."
                )
                return result

        org_role = _ROLE_ALIAS[arize_org_role]
        space_role = _ROLE_ALIAS[arize_space_role] if arize_space_role else ""

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

            if self._mapping_exists(
                space_id, org_role, space_role, attr_name, attr_value
            ):
                self.mappings_existed += 1
                result.status = "already_exists"
                self.logger.debug(
                    "Row %d: SAML mapping (%s=%s → %s, org:%s/space:%s) already exists — skipping",
                    row_number,
                    attr_name,
                    attr_value,
                    space_name,
                    arize_org_role,
                    arize_space_role or "n/a",
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
                        arize_space_role or "n/a",
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
                        arize_space_role or "n/a",
                    )
                self._saml_pending.append(
                    PendingSAMLMapping(
                        row_number=row_number,
                        org_id=org_id,
                        space_id=space_id,
                        org_role=org_role,
                        space_role=space_role,
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
