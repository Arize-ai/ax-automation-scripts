"""Orchestrator: wires the services together and processes CSV rows."""

from __future__ import annotations

import logging
import sys

from .config import ARIZE_APP_URL, ROLE_ALIAS, VALID_ORG_ROLES
from .models import PendingSAMLMapping, RowResult
from .orgs_spaces import OrgSpaceService
from .preflight import resolve_role_type_conflicts
from .roles import RolesCache
from .saml import SamlIdpService


class BulkSetupRunner:
    """End-to-end orchestrator for one CSV invocation.

    Owns a logger + run counters and composes three services (orgs/spaces,
    roles, SAML). `run(rows)` processes each row through `process_row`,
    runs the preflight conflict resolver, then flushes queued SAML mappings.
    """

    def __init__(
        self,
        api_key: str,
        dry_run: bool,
        verbose: bool,
        arize_app_url: str = ARIZE_APP_URL,
        saml_metadata_url: str | None = None,
        saml_metadata_xml: str | None = None,
        email_domains: list[str] | None = None,
        enforce_saml: bool | None = None,
        sync_user_roles: bool | None = None,
        sign_authn: bool | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.logger = self._build_logger(verbose)

        self.orgs_spaces = OrgSpaceService(
            api_key=api_key,
            logger=self.logger,
            dry_run=dry_run,
            arize_app_url=arize_app_url,
        )
        self.roles = RolesCache(api_key=api_key, logger=self.logger)
        self.saml = SamlIdpService(
            execute_graphql=self.orgs_spaces.execute_graphql,
            logger=self.logger,
            dry_run=dry_run,
            saml_metadata_url=saml_metadata_url,
            saml_metadata_xml=saml_metadata_xml,
            email_domains=email_domains,
            enforce_saml=enforce_saml,
            sync_user_roles=sync_user_roles,
            sign_authn=sign_authn,
        )

        self._init_counters()

    # ── Construction helpers ──────────────────────────────────────────────────

    @staticmethod
    def _build_logger(verbose: bool) -> logging.Logger:
        """Configure (or re-configure) the package logger; DEBUG iff verbose.

        Idempotent: clears any handlers from a previous construction so we
        don't print duplicate log lines when the runner is instantiated more
        than once in the same process (e.g. tests, embedding scripts).
        """
        logger = logging.getLogger("arize_bulk_setup")
        logger.handlers.clear()
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        logger.propagate = False
        return logger

    def _init_counters(self) -> None:
        """Reset all summary counters. Called once per runner."""
        self.orgs_created = 0
        self.orgs_existed = 0
        self.spaces_created = 0
        self.spaces_existed = 0
        self.mappings_created = 0
        self.mappings_existed = 0
        self.legacy_auto_conversions = 0
        self._counted_orgs: set[str] = set()
        self._counted_spaces: set[str] = set()

    # ── Row processor ─────────────────────────────────────────────────────────

    def process_row(self, row: dict[str, str], row_number: int) -> RowResult:
        """Validate one CSV row, resolve org/space, and queue a SAML mapping.

        Returns a `RowResult` whose `status` is one of `created`, `already_exists`,
        `dry_run`, or `error`. Errors are caught and recorded on the row rather
        than raised, so a single bad row doesn't abort the rest of the batch.
        """
        org_name = (row.get("organization") or "").strip()
        space_name = (row.get("space") or "").strip()
        arize_org_role = (row.get("arize_org_role") or "").strip().lower()
        # Preserve the raw value (case + whitespace stripped) for custom-role lookup
        # and error messages. The builtin-alias check below lowercases as needed.
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

        validation_error = _validate_row(
            org_name,
            space_name,
            arize_org_role,
            arize_space_role_raw,
            attr_name,
            attr_value,
        )
        if validation_error:
            result.status = "error"
            result.error_message = validation_error
            return result

        org_role = ROLE_ALIAS[arize_org_role]
        space_role, is_custom_space_role = _classify_space_role(arize_space_role_raw)

        try:
            org_id = self._resolve_org(org_name, row_number)
            space_id = self._resolve_space(org_id, org_name, space_name, row_number)

            # SAML is loaded by run()'s pre-flight before any row reaches here.

            # Resolve a custom RBAC role (if any) to its relay global ID.
            space_rbac_role_id = ""
            if is_custom_space_role:
                try:
                    space_rbac_role_id = self.roles.resolve_custom_space_role(
                        arize_space_role_raw
                    )
                except ValueError as exc:
                    if not self.dry_run:
                        raise
                    # Dry-run: warn but don't fail the row. Skip queuing the
                    # mapping since we don't have a relay ID, and let the
                    # operator fix the CSV (or create the role) before rerunning.
                    self.logger.warning("Row %d: %s", row_number, exc)
                    result.status = "dry_run"
                    result.note = (
                        f"Custom role '{arize_space_role_raw}' does not exist on "
                        "this account — this row would fail in a real run. "
                        "Create the role in the Arize UI or fix the CSV name, "
                        "then rerun."
                    )
                    return result

            self._process_saml_mapping(
                result=result,
                row_number=row_number,
                org_id=org_id,
                space_id=space_id,
                space_name=space_name,
                arize_org_role=arize_org_role,
                arize_space_role_raw=arize_space_role_raw,
                org_role=org_role,
                space_role=space_role,
                space_rbac_role_id=space_rbac_role_id,
                attr_name=attr_name,
                attr_value=attr_value,
            )

        except Exception as exc:
            result.status = "error"
            result.error_message = str(exc)
            # Include the traceback only at DEBUG (--verbose). At INFO, the
            # exception's str() is usually a complete GraphQL/REST error
            # payload — the Python traceback adds no actionable detail and
            # is repeated for every row that hits the same backend issue.
            self.logger.error(
                "Row %d failed: %s",
                row_number,
                exc,
                exc_info=self.logger.isEnabledFor(logging.DEBUG),
            )

        return result

    # ── process_row helpers (one concern each) ────────────────────────────────

    def _resolve_org(self, org_name: str, row_number: int) -> str:
        """Resolve an org and bump the orgs counters once per unique id."""
        org_id, org_status = self.orgs_spaces.resolve_org(org_name)
        if org_id not in self._counted_orgs:
            self._counted_orgs.add(org_id)
            if org_status in ("created", "dry_run"):
                self.orgs_created += 1
            elif org_status == "already_exists":
                self.orgs_existed += 1
        self.logger.debug(
            "Row %d: org '%s' — %s (%s)", row_number, org_name, org_status, org_id
        )
        return org_id

    def _resolve_space(
        self, org_id: str, org_name: str, space_name: str, row_number: int
    ) -> str:
        """Resolve a space and bump the spaces counters once per unique id."""
        space_id, space_status = self.orgs_spaces.resolve_space(
            org_id, org_name, space_name
        )
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
        return space_id

    def _process_saml_mapping(
        self,
        *,
        result: RowResult,
        row_number: int,
        org_id: str,
        space_id: str,
        space_name: str,
        arize_org_role: str,
        arize_space_role_raw: str,
        org_role: str,
        space_role: str,
        space_rbac_role_id: str,
        attr_name: str,
        attr_value: str,
    ) -> None:
        """Set `result.status` and either record an exact match or queue a new mapping."""
        display_space_role = arize_space_role_raw or "n/a"
        if self.saml.mapping_exists(
            space_id, org_role, space_role, space_rbac_role_id, attr_name, attr_value
        ):
            self.mappings_existed += 1
            result.status = "already_exists"
            self.saml.record_exact_match(
                row_number, space_id, space_role, space_rbac_role_id
            )
            self.logger.debug(
                "Row %d: SAML mapping (%s=%s → %s, org:%s/space:%s) already exists — skipping",
                row_number,
                attr_name,
                attr_value,
                space_name,
                arize_org_role,
                display_space_role,
            )
            return

        if self.dry_run:
            self.logger.info(
                "[DRY RUN] Row %d: Would create SAML mapping (%s=%s → %s, org:%s/space:%s)",
                row_number,
                attr_name,
                attr_value,
                space_name,
                arize_org_role,
                display_space_role,
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
                display_space_role,
            )
        self.saml.queue_mapping(
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

    # ── Top-level run ─────────────────────────────────────────────────────────

    def run(self, rows: list[dict[str, str]]) -> list[RowResult]:
        """Process all CSV rows, resolve conflicts, then flush queued SAML mappings.

        Returns one `RowResult` per input row, in the same order. The overall
        exit code is determined by the caller (`cli.main`) based on whether any
        row's final status is `error`.
        """
        # Pre-flight: load the SAML IdP once before the row loop. Without this,
        # every row would re-fire the same getSAMLIdP call and emit the same
        # error+traceback. We distinguish two distinct failures:
        #   - RuntimeError: our own _validate_creation_params — the IdP simply
        #     doesn't exist on this account and we don't have the params to
        #     create one. The message already includes actionable guidance.
        #   - Any other exception: the API call itself failed (network/auth/
        #     transport/schema) — a different problem from "IdP doesn't exist".
        try:
            self.saml.ensure_loaded()
        except RuntimeError as exc:
            self.logger.error("%s", exc)
            return [
                self._row_with_error(row, i, str(exc))
                for i, row in enumerate(rows, start=1)
            ]
        except Exception as exc:
            error_message = f"Could not load SAML configuration from Arize: {exc}"
            self.logger.exception(error_message)
            return [
                self._row_with_error(row, i, error_message)
                for i, row in enumerate(rows, start=1)
            ]

        results: list[RowResult] = []
        for i, row in enumerate(rows, start=1):
            results.append(self.process_row(row, i))

        # Client-side check that mirrors the backend rule: a space can use
        # either standard or custom roles across mappings, but not both.
        # When a CSV-internal mix is found, auto-create the legacy-equivalent
        # custom role and swap the legacy pending mappings to use it; other
        # conflict shapes still produce errors and drop the offending rows.
        results_by_row = {r.row_number: r for r in results}

        def _on_legacy_converted(
            row_number: int, legacy_key: str, custom_name: str
        ) -> None:
            self.legacy_auto_conversions += 1
            r = results_by_row.get(row_number)
            if r is not None:
                r.note = (
                    f"Auto-converted legacy '{legacy_key}' to custom role "
                    f"'{custom_name}' because this space also uses a custom role "
                    "in another mapping."
                )

        resolve_role_type_conflicts(
            saml=self.saml,
            space_id_to_name=self.orgs_spaces.space_id_to_name(),
            results=results,
            logger=self.logger,
            on_existed_to_error=self._decrement_existed_on_error,
            roles=self.roles,
            on_legacy_converted=_on_legacy_converted,
        )

        if self.dry_run:
            self.mappings_created = self.saml.pending_count()
            return results

        if not self.saml.has_pending():
            return results

        pending_rows = self.saml.pending_row_numbers()
        created_count = self.saml.pending_count()
        try:
            self.saml.flush()
            self.mappings_created += created_count
            self.logger.info("%d new SAML mapping(s) created.", created_count)
        except Exception as exc:
            self.logger.exception("Failed to flush SAML mappings: %s", exc)
            for r in results:
                # Status guard: only rows that were queued for creation in this
                # run should be flipped to error. Pre-flush errors (validation,
                # preflight conflicts, already_exists) keep their final status.
                if r.row_number in pending_rows and r.status == "created":
                    r.status = "error"
                    r.error_message = f"SAML update failed: {exc}"
        return results

    @staticmethod
    def _row_with_error(
        row: dict[str, str], row_number: int, error_message: str
    ) -> RowResult:
        """Build a RowResult that propagates the original CSV fields plus an error.

        Used by the SAML pre-flight to surface the same account-level error on
        every row without re-running validation per row.
        """
        return RowResult(
            row_number=row_number,
            organization=(row.get("organization") or "").strip(),
            space=(row.get("space") or "").strip(),
            arize_org_role=(row.get("arize_org_role") or "").strip().lower(),
            arize_space_role=(row.get("arize_space_role") or "").strip(),
            saml_attribute_name=(row.get("saml_attribute_name") or "").strip(),
            saml_attribute_value=(row.get("saml_attribute_value") or "").strip(),
            status="error",
            error_message=error_message,
        )

    def _decrement_existed_on_error(self, row_number: int) -> None:
        """Called from the preflight when a row flips already_exists → error.

        process_row optimistically bumped mappings_existed when it saw the
        already_exists state; the preflight needs to undo that bump so the
        summary reflects the row's final status.
        """
        self.mappings_existed -= 1


# ── Pure validation helpers (no I/O, easy to unit test) ──────────────────────


def _validate_row(
    org_name: str,
    space_name: str,
    arize_org_role: str,
    arize_space_role_raw: str,
    attr_name: str,
    attr_value: str,
) -> str:
    """Return an error message if the row is invalid, else empty string."""
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
        return f"Missing required field(s): {', '.join(missing)}"

    if arize_org_role not in VALID_ORG_ROLES:
        return (
            f"Invalid arize_org_role '{arize_org_role}'. "
            f"Must be one of: {', '.join(sorted(VALID_ORG_ROLES))}"
        )

    if arize_org_role == "admin" and arize_space_role_raw:
        return (
            f"Invalid combination: arize_org_role='admin' cannot be paired "
            f"with arize_space_role='{arize_space_role_raw}'. "
            "Org admins receive full org access; leave arize_space_role blank."
        )

    return ""


def _classify_space_role(arize_space_role_raw: str) -> tuple[str, bool]:
    """Classify a CSV space-role cell.

    Returns (space_role, is_custom_space_role):
      - "" / None     → ("", False) — inherit from org role
      - builtin alias → (translated_role, False) — legacy spaceRolesMap
      - anything else → ("", True)  — custom RBAC; resolved later to relay ID
    """
    if not arize_space_role_raw:
        return "", False
    lower = arize_space_role_raw.lower()
    if lower in ROLE_ALIAS:
        return ROLE_ALIAS[lower], False
    return "", True
