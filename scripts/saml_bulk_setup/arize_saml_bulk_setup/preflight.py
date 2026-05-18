"""Detect and resolve same-space mixed-role-type conflicts before the SAML flush.

Arize allows only one role type (standard OR custom) per space across all SAML
role mappings. Three distinct conflict shapes exist and need different handling:

  1. **CSV-internal (all-pending)** — two CSV rows in this run target the same
     space with mismatched role types. Instead of erroring, we auto-create
     (or look up) a custom RBAC role mirroring the legacy role's permission
     set, swap the pending legacy mapping(s) over to it, and let the run
     continue. A non-error note is stamped on the converted rows so the user
     can see what happened in the results CSV.

  2. **CSV-vs-existing** — the CSV asks for one role type for a space the IdP
     already has the other type for. That's migration intent; we strip just
     that space's existing entries (in place on the SAML service's existing
     mappings) so the new CSV row replaces them. Other entries on the
     affected mappings (other spaces, attributes, orgRole) are preserved.

  3. **already_exists + new-pending mismatch** — a CSV row matched an existing
     IdP mapping exactly (already_exists, not queued) under one role type and
     another CSV row queues a new mapping of the opposite type for the same
     space. We can't silently mutate the existing entry, so this case still
     errors with the original message.

Example (CSV-internal, auto-converted):
    organization,space,arize_org_role,arize_space_role,...
    Acme,ML Platform,member,admin,...        ← builtin space role
    Acme,ML Platform,member,Reviewer,...     ← custom space role on the same space
    → "Space Admin" custom role is created (if absent), row 1 is swapped to it,
      both rows succeed.

Example (CSV-vs-existing):
    IdP already has: ML Platform under spaceRolesMap (builtin "admin")
    CSV row:         Acme,ML Platform,member,Reviewer,...  ← custom role
    → Migration: strip "ML Platform" from the existing spaceRolesMap entry,
      let the CSV's custom-role mapping replace it.
"""

from __future__ import annotations

import logging
from typing import Callable, TYPE_CHECKING

from .models import RowResult

if TYPE_CHECKING:
    from .roles import RolesCache
    from .saml import SamlIdpService


def resolve_role_type_conflicts(
    saml: "SamlIdpService",
    space_id_to_name: dict[str, str],
    results: list[RowResult],
    logger: logging.Logger,
    on_existed_to_error: Callable[[int], None],
    roles: "RolesCache | None" = None,
    on_legacy_converted: Callable[[int, str, str], None] | None = None,
) -> None:
    """Resolve same-space mixed-role-type conflicts before the flush.

    Mutates `results` in place (error rows get status + error_message set;
    converted rows get a `note` set via `on_legacy_converted`) and may
    mutate `saml.pending` entries (legacy → custom swap) or drop them
    (preflight errors). CSV-vs-existing conflicts strip the space from the
    existing IdP mappings.

    `on_existed_to_error(row_number)` is called once per row that flips from
    `already_exists` → `error`, so the runner can decrement its counter.

    `roles` + `on_legacy_converted` enable auto-conversion of legacy CSV rows
    that conflict with a custom CSV row on the same space. When either is
    None, falls back to the legacy error behavior.
    """
    legacy_uses, rbac_uses = _collect_space_role_uses(saml)
    conflict_space_ids = set(legacy_uses) & set(rbac_uses)
    if not conflict_space_ids:
        return

    row_to_user_role = {r.row_number: r.arize_space_role for r in results}
    pending_row_numbers = saml.pending_row_numbers()

    row_errors: dict[int, str] = {}
    for space_id in conflict_space_ids:
        space_name = space_id_to_name.get(space_id, "<unknown>")
        pending_legacy_rows = sorted(
            {row for row, _ in legacy_uses[space_id] if row is not None}
        )
        pending_rbac_rows = sorted(
            {row for row, _ in rbac_uses[space_id] if row is not None}
        )
        has_existing_legacy = any(
            row is None for row, _ in legacy_uses[space_id]
        )
        has_existing_rbac = any(row is None for row, _ in rbac_uses[space_id])

        # Case 1: CSV-internal conflict. If every legacy row is truly pending
        # (not an already_exists exact-match), auto-convert; otherwise fall
        # through to the error path.
        if pending_legacy_rows and pending_rbac_rows:
            all_legacy_are_pending = (
                set(pending_legacy_rows) <= pending_row_numbers
            )
            can_auto_convert = (
                roles is not None
                and on_legacy_converted is not None
                and all_legacy_are_pending
            )
            if can_auto_convert:
                _auto_convert_legacy_rows(
                    saml=saml,
                    space_id=space_id,
                    space_name=space_name,
                    legacy_rows=pending_legacy_rows,
                    roles=roles,  # type: ignore[arg-type]
                    on_legacy_converted=on_legacy_converted,  # type: ignore[arg-type]
                    logger=logger,
                )
                continue
            message = _build_csv_internal_message(
                space_name,
                pending_legacy_rows,
                pending_rbac_rows,
                row_to_user_role,
            )
            for row in pending_legacy_rows + pending_rbac_rows:
                row_errors[row] = message
            continue

        # Case 2: CSV-vs-existing conflict — migration. Strip in place.
        if pending_legacy_rows and has_existing_rbac:
            saml.strip_space(space_id, key="spaceRbacRolesMap")
        elif pending_rbac_rows and has_existing_legacy:
            saml.strip_space(space_id, key="spaceRolesMap")
        # Else: only existing entries collide (no pending touches this space).
        # Not the script's job to fix pre-existing IdP state.

    if not row_errors:
        return

    for r in results:
        if r.row_number not in row_errors:
            continue
        # If the row had previously been marked already_exists, the counter
        # was bumped optimistically; let the caller back it out so the
        # summary reflects the final error status.
        if r.status == "already_exists":
            on_existed_to_error(r.row_number)
        r.status = "error"
        r.error_message = row_errors[r.row_number]
        logger.error("Row %d: %s", r.row_number, r.error_message)

    saml.drop_pending(set(row_errors.keys()))


def _auto_convert_legacy_rows(
    *,
    saml: "SamlIdpService",
    space_id: str,
    space_name: str,
    legacy_rows: list[int],
    roles: "RolesCache",
    on_legacy_converted: Callable[[int, str, str], None],
    logger: logging.Logger,
) -> None:
    """Convert each pending legacy mapping for `space_id` to its custom equivalent.

    Idempotent — `RolesCache.ensure_legacy_equivalent_role` looks up the cached
    role first and only POSTs /v2/roles when the equivalent doesn't yet exist.
    """
    for row in legacy_rows:
        outcome = saml.convert_legacy_to_custom(row, space_id, roles)
        if outcome is None:
            # Defensive: caller already verified rows are pending. Treat any
            # gap as a logical error so we don't silently drop the row's intent.
            raise RuntimeError(
                f"Row {row}: expected a pending legacy mapping for space "
                f"'{space_name}' ({space_id}) but found none."
            )
        legacy_key, custom_name = outcome
        on_legacy_converted(row, legacy_key, custom_name)
        logger.info(
            "Row %d: auto-converted legacy '%s' → custom role '%s' "
            "(space '%s' uses a custom role in another mapping)",
            row,
            legacy_key,
            custom_name,
            space_name,
        )


def _collect_space_role_uses(
    saml: "SamlIdpService",
) -> tuple[
    dict[str, list[tuple[int | None, str]]],
    dict[str, list[tuple[int | None, str]]],
]:
    """For every space_id, list who's using it under each role-type.

    Entry tuple is (csv_row_number_or_None, label). row_number is None for
    an existing IdP mapping; integer for a CSV row (pending or already_exists).
    """
    legacy_uses: dict[str, list[tuple[int | None, str]]] = {}
    rbac_uses: dict[str, list[tuple[int | None, str]]] = {}

    for mapping in saml.existing_mappings:
        for pair in mapping.get("spaceRolesMap") or []:
            if len(pair) >= 2 and pair[0]:
                legacy_uses.setdefault(pair[0], []).append((None, "standard"))
        for pair in mapping.get("spaceRbacRolesMap") or []:
            if len(pair) >= 2 and pair[0]:
                rbac_uses.setdefault(pair[0], []).append((None, "custom"))

    for p in saml.pending:
        if p.space_rbac_role_id:
            rbac_uses.setdefault(p.space_id, []).append((p.row_number, "custom"))
        elif p.space_role:
            legacy_uses.setdefault(p.space_id, []).append(
                (p.row_number, "standard")
            )

    # Exact-match (already_exists) rows also express the CSV's intent for a
    # space's role-type. Include them so the preflight can detect a CSV that
    # asks to keep an existing entry on one row while migrating it on another.
    for row_number, space_id, space_role, space_rbac_role_id in saml.exact_match_uses:
        if space_rbac_role_id:
            rbac_uses.setdefault(space_id, []).append((row_number, "custom"))
        elif space_role:
            legacy_uses.setdefault(space_id, []).append((row_number, "standard"))

    return legacy_uses, rbac_uses


def _build_csv_internal_message(
    space_name: str,
    pending_legacy_rows: list[int],
    pending_rbac_rows: list[int],
    row_to_user_role: dict[int, str],
) -> str:
    def describe(rows: list[int]) -> str:
        return ", ".join(
            f"row {r} ('{row_to_user_role.get(r, '')}')" for r in rows
        )

    return (
        f"Space '{space_name}' would receive both a standard role and "
        f"a custom role from your CSV, which Arize does not allow. "
        f"Each space must use only one role type. Conflicts: "
        f"standard role in {describe(pending_legacy_rows)}; "
        f"custom role in {describe(pending_rbac_rows)}. "
        f"Please edit the CSV so this space uses either standard roles "
        f"(admin/member/viewer/annotator) or a custom role — not both."
    )
