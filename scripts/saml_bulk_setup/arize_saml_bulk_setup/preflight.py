"""Detect and resolve same-space mixed-role-type conflicts before the SAML flush.

Arize allows only one role type (standard OR custom) per space across all SAML
role mappings. Whenever the run produces a same-space legacy + custom conflict,
this module promotes every legacy use on that space to a custom RBAC role
mirroring its permission set. Custom is never demoted to legacy (the built-in
legacy roles are fixed sets), so promotion is the only non-destructive way out.

Two conflict shapes exist — both involve a CSV row touching the space, since
Arize's backend (and UI) prevents pre-existing mixed state on a space:

  1. **CSV-internal** — two CSV rows in this run target the same space with
     mismatched role types. The pending legacy row(s) are auto-converted to
     the legacy-equivalent custom role and the run continues.

  2. **CSV-vs-existing** — the CSV touches a space (either a pending row or an
     already_exists match) for which the IdP already holds the other role
     type. Every legacy use on that space is promoted — pending rows AND any
     pre-existing IdP entries. Matched rows keep status `already_exists` but
     gain a note explaining the promotion. The existing custom-role mapping is
     preserved.

Example (CSV-internal):
    organization,space,arize_org_role,arize_space_role,...
    Acme,ML Platform,member,admin,...        ← builtin space role
    Acme,ML Platform,member,Reviewer,...     ← custom space role on the same space
    → "Space Admin" custom role is created (if absent), row 1 is swapped to it,
      both rows succeed.

Example (CSV-vs-existing with matched row — the case behind this change):
    IdP already has: NLP Research under spaceRolesMap (builtin "member") via
                     attributes [["roles", "arize-nlp-research"]]
    CSV row 6:       Acme,NLP Research,member,Testing Custom Roles,roles,arize-nlp-leads
    CSV row 7:       Acme,NLP Research,member,member,roles,arize-nlp-research     ← matches existing
    → "Space Member" custom role is created/looked up; the existing legacy
      pair is moved from spaceRolesMap to spaceRbacRolesMap under the same
      mapping. Row 6 ends up `created`/`dry_run`; row 7 stays `already_exists`
      with a note about the promotion.
"""

from __future__ import annotations

import logging
from typing import Callable, TYPE_CHECKING

from .models import RowResult

if TYPE_CHECKING:
    from .roles import RolesCache
    from .saml import SamlIdpService


# Callback signature: (row_number, legacy_key, custom_name, kind)
# kind is "pending" (the row's queued mapping was swapped) or "matched"
# (the existing IdP mapping the row matched was promoted in place).
OnLegacyConverted = Callable[[int, str, str, str], None]


def resolve_role_type_conflicts(
    saml: "SamlIdpService",
    space_id_to_name: dict[str, str],
    results: list[RowResult],
    logger: logging.Logger,
    on_existed_to_error: Callable[[int], None],
    roles: "RolesCache | None" = None,
    on_legacy_converted: OnLegacyConverted | None = None,
) -> None:
    """Resolve same-space mixed-role-type conflicts before the flush.

    For every conflicted `space_id` the CSV touches, promote all legacy uses
    on that space to the legacy-equivalent custom role:

      - pending legacy rows are swapped via `saml.convert_legacy_to_custom`
      - existing legacy IdP entries on the space are rewritten in place via
        `saml.promote_existing_legacy_for_space`
      - matched (already_exists) rows whose existing entry was promoted get
        a non-error `note` (status stays `already_exists`)

    Mutates `results` in place. May mutate `saml._pending` and
    `saml._existing_mappings`.

    `roles` + `on_legacy_converted` enable the promotion. When either is
    `None`, or if the role lookup/creation raises, falls back to the original
    error message so the run doesn't silently misbehave.
    """
    legacy_uses, rbac_uses = _collect_space_role_uses(saml)
    conflict_space_ids = set(legacy_uses) & set(rbac_uses)
    if not conflict_space_ids:
        return

    row_to_user_role = {r.row_number: r.arize_space_role for r in results}
    pending_row_numbers = saml.pending_row_numbers()

    can_promote = roles is not None and on_legacy_converted is not None
    row_errors: dict[int, str] = {}

    for space_id in conflict_space_ids:
        space_name = space_id_to_name.get(space_id, "<unknown>")
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

        # Promote every legacy use to custom.
        if not can_promote:
            message = _build_conflict_message(
                space_name,
                pending_legacy_rows,
                pending_rbac_rows,
                matched_legacy_rows,
                matched_rbac_rows,
                row_to_user_role,
            )
            for row in (
                pending_legacy_rows
                + pending_rbac_rows
                + matched_legacy_rows
                + matched_rbac_rows
            ):
                row_errors[row] = message
            continue

        try:
            _promote_legacy_for_space(
                saml=saml,
                roles=roles,  # type: ignore[arg-type]
                on_legacy_converted=on_legacy_converted,  # type: ignore[arg-type]
                space_id=space_id,
                space_name=space_name,
                pending_legacy_rows=pending_legacy_rows,
                matched_legacy_rows=matched_legacy_rows,
                has_existing_legacy=has_existing_legacy,
                logger=logger,
            )
        except Exception as exc:
            # Role lookup/creation failed — fall back to the error path so the
            # user sees a clear message rather than a half-converted IdP.
            logger.error(
                "Failed to auto-promote legacy roles for space '%s' (%s): %s",
                space_name,
                space_id,
                exc,
            )
            message = _build_conflict_message(
                space_name,
                pending_legacy_rows,
                pending_rbac_rows,
                matched_legacy_rows,
                matched_rbac_rows,
                row_to_user_role,
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

    saml.drop_pending(set(row_errors.keys()))


def _promote_legacy_for_space(
    *,
    saml: "SamlIdpService",
    roles: "RolesCache",
    on_legacy_converted: OnLegacyConverted,
    space_id: str,
    space_name: str,
    pending_legacy_rows: list[int],
    matched_legacy_rows: list[int],
    has_existing_legacy: bool,
    logger: logging.Logger,
) -> None:
    """Promote every legacy use on `space_id` to its custom equivalent.

    Sources:
      - pending CSV rows queued under spaceRolesMap → swapped via convert_legacy_to_custom
      - existing IdP entries on the space (matched or not) → rewritten via
        promote_existing_legacy_for_space
      - matched rows are annotated via on_legacy_converted(kind="matched")
    """
    # 1. Convert pending legacy rows in `_pending`.
    for row in pending_legacy_rows:
        outcome = saml.convert_legacy_to_custom(row, space_id, roles)
        if outcome is None:
            # Defensive: caller filtered for pending; treat as bug.
            raise RuntimeError(
                f"Row {row}: expected a pending legacy mapping for space "
                f"'{space_name}' ({space_id}) but found none."
            )
        legacy_key, custom_name = outcome
        on_legacy_converted(row, legacy_key, custom_name, "pending")
        logger.info(
            "Row %d: auto-converted legacy '%s' → custom role '%s' "
            "(space '%s' uses a custom role in another mapping)",
            row,
            legacy_key,
            custom_name,
            space_name,
        )

    # 2. Promote existing IdP legacy entries for this space (matched or orphan).
    #    Skip if no existing legacy on the space — promote is a no-op anyway,
    #    but skipping keeps the log clean.
    if has_existing_legacy:
        conversions = saml.promote_existing_legacy_for_space(space_id, roles)
        for legacy_key, custom_name in conversions:
            logger.info(
                "Auto-promoted existing legacy '%s' → custom role '%s' on "
                "space '%s' (another mapping uses a custom role)",
                legacy_key,
                custom_name,
                space_name,
            )

        # 3. Annotate every matched row whose underlying entry just got promoted.
        #    The mapping was preserved (just under a different role type), so
        #    the row's status stays `already_exists`.
        if conversions and matched_legacy_rows:
            # Pick a representative (legacy_key, custom_name) per matched row.
            # In the typical case there's one legacy key on the space; if
            # multiple, the first conversion is a reasonable summary for the
            # note. The full breakdown shows up in the log above.
            rep_key, rep_name = conversions[0]
            for row in matched_legacy_rows:
                on_legacy_converted(row, rep_key, rep_name, "matched")


def _collect_space_role_uses(
    saml: "SamlIdpService",
) -> tuple[
    dict[str, list[tuple[int | None, str]]],
    dict[str, list[tuple[int | None, str]]],
]:
    """For every space_id, list who's using it under each role-type.

    Entry tuple is (csv_row_number_or_None, label). row_number is None for
    an existing IdP mapping that no CSV row matched; integer for a CSV row
    (pending or already_exists).
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
            legacy_uses.setdefault(p.space_id, []).append((p.row_number, "standard"))

    # Exact-match (already_exists) rows also express the CSV's intent for a
    # space's role-type. Include them so the preflight can detect a CSV that
    # asks to keep an existing entry on one row while migrating it on another.
    for row_number, space_id, space_role, space_rbac_role_id in saml.exact_match_uses:
        if space_rbac_role_id:
            rbac_uses.setdefault(space_id, []).append((row_number, "custom"))
        elif space_role:
            legacy_uses.setdefault(space_id, []).append((row_number, "standard"))

    return legacy_uses, rbac_uses


def _build_conflict_message(
    space_name: str,
    pending_legacy_rows: list[int],
    pending_rbac_rows: list[int],
    matched_legacy_rows: list[int],
    matched_rbac_rows: list[int],
    row_to_user_role: dict[int, str],
) -> str:
    """Compose the fallback error message used when auto-promotion is unavailable."""

    def describe(rows: list[int]) -> str:
        return (
            ", ".join(f"row {r} ('{row_to_user_role.get(r, '')}')" for r in rows)
            or "(none)"
        )

    return (
        f"Space '{space_name}' would receive both a standard role and "
        f"a custom role across SAML mappings, which Arize does not allow. "
        f"Each space must use only one role type. Conflicts: "
        f"standard role in {describe(pending_legacy_rows + matched_legacy_rows)}; "
        f"custom role in {describe(pending_rbac_rows + matched_rbac_rows)}. "
        f"Auto-promotion to a custom role mirroring the legacy permissions "
        f"is unavailable (RolesCache not provided or POST /v2/roles failed). "
        f"Please edit the CSV so this space uses either standard roles "
        f"(admin/member/viewer/annotator) or a custom role — not both."
    )
