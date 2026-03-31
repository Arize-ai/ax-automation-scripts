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

# arize_toolkit — used for all org/space operations it supports:
#   get_all_organizations(), get_all_spaces(), create_new_space()
from arize_toolkit import Client as ArizeClient

# Raw GQL — only for operations not covered by arize_toolkit:
#   createOrganization, getSAMLIdP, updateSAMLIdP
from gql import gql

# ─── Constants ───────────────────────────────────────────────────────────────

ARIZE_APP_URL = "https://app.arize.com"
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

VALID_ROLES = {"admin", "member", "viewer"}

# PRD uses "viewer"; Arize GraphQL schema uses "readOnly"
ROLE_ALIAS: dict[str, str] = {
    "admin": "admin",
    "member": "member",
    "viewer": "readOnly",
}

OUTPUT_COLUMNS = [
    "organization",
    "space",
    "arize_role",
    "saml_attribute_name",
    "saml_attribute_value",
    "status",
    "error_message",
]

# ─── Raw GraphQL — only for operations not in arize_toolkit ──────────────────

# arize_toolkit has no createOrganization method
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

# arize_toolkit has no SAML operations
_GET_SAML_IDP = gql("""
    query getSAMLIdP {
        account {
            samlIdPs(first: 1) {
                edges {
                    node {
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
    arize_role: str
    saml_attribute_name: str
    saml_attribute_value: str
    status: str = ""
    error_message: str = ""


@dataclass
class PendingSAMLMapping:
    """A new SAML role mapping queued for creation, tied back to a CSV row."""
    row_number: int
    space_id: str
    space_role: str   # translated: "admin" | "member" | "readOnly"
    attr_name: str
    attr_value: str


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
    last_exc: Optional[Exception] = None
    for attempt in range(MAX_RETRIES):
        try:
            return fn()
        except Exception as exc:
            if _is_rate_limit_error(exc) and attempt < MAX_RETRIES - 1:
                wait = INITIAL_BACKOFF * (2 ** attempt)
                logger.warning(
                    "Rate limit hit for '%s' (attempt %d/%d). Retrying in %.1fs…",
                    operation_name, attempt + 1, MAX_RETRIES, wait,
                )
                time.sleep(wait)
                last_exc = exc
            else:
                raise
    raise RuntimeError(
        f"All {MAX_RETRIES} retries exhausted for '{operation_name}'"
    ) from last_exc


# ─── Main runner ─────────────────────────────────────────────────────────────

class BulkSetupRunner:
    def __init__(
        self,
        api_key: str,
        dry_run: bool,
        verbose: bool,
        arize_app_url: str = ARIZE_APP_URL,
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
        # _graphql_client is the underlying gql.Client; used only for the three
        # operations arize_toolkit does not cover (createOrganization, SAML).
        self._gql = self._toolkit._graphql_client

        # In-memory caches
        self._org_cache: dict[str, str] = {}            # org_name → org_id
        self._org_cache_loaded = False
        self._space_cache: dict[tuple[str, str], str] = {}  # (org_id, space_name) → space_id
        self._spaces_loaded_for: set[str] = set()        # org_ids already fetched

        # SAML state — loaded once on first SAML operation
        self._saml_idp_id: Optional[str] = None
        self._saml_existing_mappings: list[dict] = []
        self._saml_pending: list[PendingSAMLMapping] = []

        # Run counters
        self.orgs_created = 0
        self.orgs_existed = 0
        self.spaces_created = 0
        self.spaces_existed = 0
        self.mappings_created = 0
        self.mappings_existed = 0

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
        self.logger.debug("Loading all organizations via arize_toolkit…")
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

        # createOrganization is not in arize_toolkit — use raw GQL
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
        self.logger.debug("Loading spaces for org '%s' via arize_toolkit…", org_name)
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

    def _resolve_space(self, org_id: str, org_name: str, space_name: str) -> tuple[str, str]:
        """Return (space_id, status). Creates the space if it doesn't exist."""
        self._load_spaces_for_org(org_id, org_name)

        cache_key = (org_id, space_name)
        if cache_key in self._space_cache:
            return self._space_cache[cache_key], "already_exists"

        self.logger.info("Creating space '%s' in org '%s' via arize_toolkit…", space_name, org_name)
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
        """Load the account's SAMLIdP and its existing role mappings (once)."""
        if self._saml_idp_id is not None:
            return
        self.logger.debug("Loading SAML IdP (raw GQL — not in arize_toolkit)…")
        result = with_retry(
            lambda: self._gql.execute(_GET_SAML_IDP, variable_values={}),
            "getSAMLIdP",
            self.logger,
        )
        edges = result["account"]["samlIdPs"]["edges"]
        if not edges:
            raise RuntimeError(
                "No SAML IdP found for this account. "
                "Configure SAML in the Arize UI before running this script."
            )
        idp = edges[0]["node"]
        self._saml_idp_id = idp["id"]
        self._saml_existing_mappings = idp.get("roleMappings") or []
        self.logger.debug(
            "Found SAMLIdP %s with %d existing role mapping(s)",
            self._saml_idp_id,
            len(self._saml_existing_mappings),
        )

    def _mapping_exists(
        self, space_id: str, space_role: str, attr_name: str, attr_value: str
    ) -> bool:
        """True if any existing or already-queued mapping covers this combo."""
        for mapping in self._saml_existing_mappings:
            attrs = mapping.get("attributesMap") or []
            spaces = mapping.get("spaceRolesMap") or []
            has_attr = any(
                len(p) >= 2 and p[0] == attr_name and p[1] == attr_value
                for p in attrs
            )
            has_space_role = any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_role
                for p in spaces
            )
            if has_attr and has_space_role:
                return True
        # Also deduplicate within the current run
        return any(
            p.space_id == space_id
            and p.space_role == space_role
            and p.attr_name == attr_name
            and p.attr_value == attr_value
            for p in self._saml_pending
        )

    def _flush_saml_mappings(self) -> None:
        """One updateSAMLIdP call that adds all pending new mappings.

        updateSAMLIdP is a full-replace operation — we send existing mappings
        (with their IDs preserved) plus the new ones.
        """
        if not self._saml_pending or self._saml_idp_id is None:
            return

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

        for p in self._saml_pending:
            mappings_input.append({
                "attributesMap": [[p.attr_name, p.attr_value]],
                "spaceRolesMap": [[p.space_id, p.space_role]],
                "isAccountAdmin": False,
            })

        self.logger.info(
            "Updating SAMLIdP (raw GQL): %d existing + %d new mapping(s)",
            len(self._saml_existing_mappings),
            len(self._saml_pending),
        )
        result = with_retry(
            lambda: self._gql.execute(
                _UPDATE_SAML_IDP,
                variable_values={
                    "input": {
                        "id": self._saml_idp_id,
                        "roleMappings": {"mappingsList": mappings_input},
                    }
                },
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
        org_name = row["organization"].strip()
        space_name = row["space"].strip()
        arize_role = row["arize_role"].strip().lower()
        attr_name = row["saml_attribute_name"].strip()
        attr_value = row["saml_attribute_value"].strip()

        result = RowResult(
            row_number=row_number,
            organization=org_name,
            space=space_name,
            arize_role=arize_role,
            saml_attribute_name=attr_name,
            saml_attribute_value=attr_value,
        )

        if arize_role not in VALID_ROLES:
            result.status = "error"
            result.error_message = (
                f"Invalid arize_role '{arize_role}'. "
                f"Must be one of: {', '.join(sorted(VALID_ROLES))}"
            )
            return result

        space_role = ROLE_ALIAS[arize_role]

        try:
            # 1. Resolve org (arize_toolkit: get_all_organizations / raw GQL: createOrganization)
            org_id, org_status = self._resolve_org(org_name)
            if org_status == "created":
                self.orgs_created += 1
            elif org_status == "already_exists":
                self.orgs_existed += 1
            self.logger.debug(
                "Row %d: org '%s' — %s (%s)", row_number, org_name, org_status, org_id
            )

            # 2. Resolve space (arize_toolkit: get_all_spaces / create_new_space)
            space_id, space_status = self._resolve_space(org_id, org_name, space_name)
            if space_status == "created":
                self.spaces_created += 1
            elif space_status == "already_exists":
                self.spaces_existed += 1
            self.logger.debug(
                "Row %d: space '%s' — %s (%s)", row_number, space_name, space_status, space_id
            )

            # 3. SAML mapping (raw GQL — arize_toolkit has no SAML support)
            self._load_saml_idp()

            if self._mapping_exists(space_id, space_role, attr_name, attr_value):
                self.mappings_existed += 1
                result.status = "already_exists"
                self.logger.debug(
                    "Row %d: SAML mapping (%s=%s → %s/%s) already exists — skipping",
                    row_number, attr_name, attr_value, space_name, arize_role,
                )
            else:
                if self.dry_run:
                    self.logger.info(
                        "[DRY RUN] Row %d: Would create SAML mapping "
                        "(%s=%s → %s/%s)",
                        row_number, attr_name, attr_value, space_name, arize_role,
                    )
                    result.status = "dry_run"
                else:
                    self._saml_pending.append(PendingSAMLMapping(
                        row_number=row_number,
                        space_id=space_id,
                        space_role=space_role,
                        attr_name=attr_name,
                        attr_value=attr_value,
                    ))
                    result.status = "created"
                    self.logger.debug(
                        "Row %d: SAML mapping (%s=%s → %s/%s) queued",
                        row_number, attr_name, attr_value, space_name, arize_role,
                    )

        except Exception as exc:
            result.status = "error"
            result.error_message = str(exc)
            self.logger.error("Row %d failed: %s", row_number, exc)

        return result

    # ── Top-level run ─────────────────────────────────────────────────────────

    def run(self, rows: list[dict]) -> list[RowResult]:
        results: list[RowResult] = []

        for i, row in enumerate(rows, start=2):  # row 1 = header
            results.append(self.process_row(row, i))

        # Flush all queued SAML mappings in a single updateSAMLIdP call
        if self._saml_pending and not self.dry_run:
            try:
                self._flush_saml_mappings()
                self.mappings_created += len(self._saml_pending)
                self.logger.info("%d new SAML mapping(s) created.", len(self._saml_pending))
            except Exception as exc:
                self.logger.error("Failed to flush SAML mappings: %s", exc)
                pending_rows = {p.row_number for p in self._saml_pending}
                for r in results:
                    if r.row_number in pending_rows and r.status == "created":
                        r.status = "error"
                        r.error_message = f"SAML update failed: {exc}"
        elif self.dry_run and self._saml_pending:
            self.logger.info(
                "[DRY RUN] Would create %d new SAML mapping(s).",
                len(self._saml_pending),
            )

        return results


# ─── CSV helpers ─────────────────────────────────────────────────────────────

REQUIRED_COLUMNS = {
    "organization", "space", "arize_role",
    "saml_attribute_name", "saml_attribute_value",
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
        rows = [row for row in reader if any(v.strip() for v in row.values())]
    if not rows:
        print("ERROR: CSV file has no data rows.", file=sys.stderr)
        sys.exit(1)
    return rows


def write_results_csv(results: list[RowResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "organization": r.organization,
                "space": r.space,
                "arize_role": r.arize_role,
                "saml_attribute_name": r.saml_attribute_name,
                "saml_attribute_value": r.saml_attribute_value,
                "status": r.status,
                "error_message": r.error_message,
            })


# ─── Summary printer ─────────────────────────────────────────────────────────

def print_summary(
    runner: BulkSetupRunner, results: list[RowResult], output_path: str
) -> None:
    errors = [r for r in results if r.status == "error"]
    print()
    print("─" * 50)
    print("Summary")
    print("─" * 50)
    print(f"  Organizations : {runner.orgs_created} created, {runner.orgs_existed} already existed")
    print(f"  Spaces        : {runner.spaces_created} created, {runner.spaces_existed} already existed")
    print(f"  SAML mappings : {runner.mappings_created} created, {runner.mappings_existed} already existed")
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
    parser.add_argument("--csv", required=True, metavar="CSV", help="Path to input CSV file")
    parser.add_argument(
        "--api-key",
        metavar="API_KEY",
        help="Arize API key (or set ARIZE_API_KEY / ARIZE_DEVELOPER_KEY env var)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without API calls")
    parser.add_argument("--verbose", action="store_true", help="Enable per-row debug logging")
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

    api_key = resolve_api_key(args.api_key)
    rows = load_csv(args.csv)

    if args.dry_run:
        print("DRY RUN — no changes will be made.\n")

    runner = BulkSetupRunner(
        api_key=api_key,
        dry_run=args.dry_run,
        verbose=args.verbose,
        arize_app_url=args.arize_url,
    )

    results = runner.run(rows)

    write_results_csv(results, args.output)
    print_summary(runner, results, args.output)

    sys.exit(1 if any(r.status == "error" for r in results) else 0)


if __name__ == "__main__":
    main()
