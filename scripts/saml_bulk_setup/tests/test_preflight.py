"""Preflight role-type conflict resolution — covers TEST_SCENARIOS.md section 6.

  6.1 — Shape A (CSV-internal pending mix): auto-converts pending legacy → custom.
  6.2 — Shape B (pending legacy + existing custom on same space):
        pending legacy is converted; existing custom mapping preserved (no strip).
  6.3 — Shape C (pending custom + existing legacy on same space):
        existing legacy IdP entry is rewritten in place to spaceRbacRolesMap.
  6.4 — Shape D (already_exists matched legacy + pending custom on same space):
        both rows succeed. Matched row keeps status='already_exists' with a note.
  6.5 — Shape E (already_exists matched custom + pending legacy on same space):
        pending legacy is converted (via the existing pending-conversion path).
  6.6 — Failure path: roles lookup raises → fallback to error message.
  6.7 — Multiple legacy keys on the same conflicted space across mappings.
"""

from __future__ import annotations

import logging

import pytest

from arize_saml_bulk_setup.models import PendingSAMLMapping, RowResult
from arize_saml_bulk_setup.preflight import resolve_role_type_conflicts


class FakeSaml:
    """Stand-in for SamlIdpService that the preflight reads from / mutates.

    Implements only the surface the preflight touches: existing_mappings,
    pending, exact_match_uses, drop_pending, pending_row_numbers,
    convert_legacy_to_custom, promote_existing_legacy_for_space.
    """

    def __init__(
        self,
        existing_mappings: list[dict] | None = None,
        pending: list[PendingSAMLMapping] | None = None,
        exact_match_uses: list[tuple[int, str, str, str]] | None = None,
    ) -> None:
        self._existing = list(existing_mappings or [])
        self._pending = list(pending or [])
        self._exact = list(exact_match_uses or [])
        self.convert_calls: list[tuple[int, str]] = []
        self.promote_calls: list[str] = []

    # Properties match the real service's tuple-view contract
    @property
    def existing_mappings(self) -> tuple[dict, ...]:
        return tuple(self._existing)

    @property
    def pending(self) -> tuple[PendingSAMLMapping, ...]:
        return tuple(self._pending)

    @property
    def exact_match_uses(self) -> tuple[tuple[int, str, str, str], ...]:
        return tuple(self._exact)

    def pending_row_numbers(self) -> set[int]:
        return {p.row_number for p in self._pending}

    def drop_pending(self, row_numbers: set[int]) -> None:
        self._pending = [
            p for p in self._pending if p.row_number not in row_numbers
        ]

    def convert_legacy_to_custom(
        self, row_number: int, space_id: str, roles: "FakeRoles"
    ) -> tuple[str, str] | None:
        for p in self._pending:
            if (
                p.row_number == row_number
                and p.space_id == space_id
                and p.space_role
                and not p.space_rbac_role_id
            ):
                self.convert_calls.append((row_number, space_id))
                legacy_key = p.space_role
                relay_id, custom_name = roles.ensure_legacy_equivalent_role(
                    legacy_key
                )
                p.space_rbac_role_id = relay_id
                p.space_role = ""
                return legacy_key, custom_name
        return None

    def promote_existing_legacy_for_space(
        self, space_id: str, roles: "FakeRoles"
    ) -> list[tuple[str, str]]:
        """Mimic SamlIdpService.promote_existing_legacy_for_space."""
        self.promote_calls.append(space_id)
        conversions: dict[str, str] = {}
        for mapping in self._existing:
            legacy = mapping.get("spaceRolesMap") or []
            if not legacy:
                continue
            kept: list[list[str]] = []
            for pair in legacy:
                if len(pair) < 2 or pair[0] != space_id:
                    kept.append(pair)
                    continue
                legacy_key = pair[1]
                relay_id, custom_name = roles.ensure_legacy_equivalent_role(
                    legacy_key
                )
                conversions[legacy_key] = custom_name
                rbac = mapping.get("spaceRbacRolesMap")
                if rbac is None:
                    rbac = []
                    mapping["spaceRbacRolesMap"] = rbac
                rbac.append([space_id, relay_id])
            mapping["spaceRolesMap"] = kept
        return list(conversions.items())


class FakeRoles:
    """Records ensure_legacy_equivalent_role calls and hands back a deterministic relay ID."""

    def __init__(self, mapping: dict[str, tuple[str, str]] | None = None) -> None:
        self.mapping = mapping or {
            "admin": ("Um9sZTpBRE1JTg==", "Space Admin"),
            "member": ("Um9sZTpNRU1CRVI=", "Space Member"),
            "readOnly": ("Um9sZTpSRUFE", "Space Read-Only"),
            "annotator": ("Um9sZTpBTk5PVA==", "Space Annotator"),
        }
        self.calls: list[str] = []
        self.raise_on: set[str] = set()

    def ensure_legacy_equivalent_role(
        self, legacy_role_key: str
    ) -> tuple[str, str]:
        self.calls.append(legacy_role_key)
        if legacy_role_key in self.raise_on:
            raise RuntimeError(f"simulated POST /v2/roles failure for {legacy_role_key}")
        return self.mapping[legacy_role_key]


def _result(
    row_number: int,
    space: str = "ML Platform",
    space_role: str = "",
    status: str = "created",
) -> RowResult:
    return RowResult(
        row_number=row_number,
        organization="Acme Corp",
        space=space,
        arize_org_role="member",
        arize_space_role=space_role,
        saml_attribute_name="groups",
        saml_attribute_value=f"g{row_number}",
        status=status,
    )


def _record_conversion(sink: list[tuple[int, str, str, str]]):
    def _cb(
        row_number: int, legacy_key: str, custom_name: str, kind: str = "pending"
    ) -> None:
        sink.append((row_number, legacy_key, custom_name, kind))

    return _cb


# ── Shape A: CSV-internal pending mix ────────────────────────────────────────


def test_csv_internal_mix_auto_converts_legacy_to_custom(
    logger: logging.Logger,
) -> None:
    """6.1: pending legacy + pending custom on same space → legacy row swapped."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="admin", space_rbac_role_id="",
                attr_name="groups", attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="admin"),
        _result(2, space_role="Project Reviewer"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    rollback_calls: list[int] = []
    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=rollback_calls.append,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    assert results[0].status == "created"
    assert results[1].status == "created"
    assert not results[0].error_message
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_role == ""
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTpBRE1JTg=="
    assert roles.calls == ["admin"]
    assert conversions == [(1, "admin", "Space Admin", "pending")]
    assert rollback_calls == []


def test_csv_internal_mix_falls_back_to_error_when_roles_not_provided(
    logger: logging.Logger,
) -> None:
    """Backward-compat: when roles is None the preflight still produces errors."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="admin", space_rbac_role_id="",
                attr_name="groups", attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="admin"),
        _result(2, space_role="Project Reviewer"),
    ]

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
    )

    assert results[0].status == "error"
    assert results[1].status == "error"
    assert "row 1 ('admin')" in results[0].error_message
    assert saml.pending == ()


def test_annotator_legacy_is_auto_converted(logger: logging.Logger) -> None:
    """Auto-conversion works for all four legacy keys, including annotator."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="annotator",
                space_role="annotator", space_rbac_role_id="",
                attr_name="groups", attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="annotator"),
        _result(2, space_role="Project Reviewer"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    assert roles.calls == ["annotator"]
    assert conversions == [(1, "annotator", "Space Annotator", "pending")]
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTpBTk5PVA=="


# ── Shape B: pending legacy + existing custom (was strip; now promote pending) ───


def test_shape_b_pending_legacy_existing_custom_preserves_custom(
    logger: logging.Logger,
) -> None:
    """6.2: existing custom-role mapping stays put; pending legacy is converted."""
    existing = [
        {
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpFWElTVA=="]],
            "attributesMap": [["groups", "existing-custom"]],
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="member", space_rbac_role_id="",
                attr_name="groups", attr_value="new-legacy",
            )
        ],
    )
    results = [_result(1, space_role="member")]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    # Pending row converted via legacy-equivalent custom role
    assert results[0].status == "created"
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_role == ""
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTpNRU1CRVI="
    # Existing custom mapping was NOT touched
    assert existing[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpFWElTVA=="]]
    # No existing-legacy promotion happened (none existed) — but the helper may
    # still have been called depending on impl; assert the result instead.
    assert conversions == [(1, "member", "Space Member", "pending")]


# ── Shape C: pending custom + existing legacy (was strip; now promote existing) ──


def test_shape_c_pending_custom_promotes_existing_legacy(
    logger: logging.Logger,
) -> None:
    """6.3: existing legacy IdP entry is rewritten in place to spaceRbacRolesMap."""
    existing = [
        {
            "spaceRolesMap": [["S1", "admin"], ["S2", "member"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "g_existing"]],
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g_new_custom",
            )
        ],
    )
    results = [_result(1, space="ML Platform", space_role="Project Reviewer")]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform", "S2": "Fraud Detection"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    # S1's legacy pair moved to spaceRbacRolesMap; S2 stays under spaceRolesMap.
    assert existing[0]["spaceRolesMap"] == [["S2", "member"]]
    assert existing[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert saml.promote_calls == ["S1"]
    # Pending row stays as-is (already custom).
    assert results[0].status == "created"
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTox"
    # No row-targeted conversion fired (no matched row on this space).
    assert conversions == []


# ── Shape D: matched legacy + pending custom (the reported failure) ──────────


def test_shape_d_matched_legacy_plus_pending_custom_promotes_and_annotates(
    logger: logging.Logger,
) -> None:
    """6.4: an already_exists row matched an existing legacy mapping; another CSV row
    adds a custom role on the same space. Both succeed; matched row gets a note."""
    existing = [
        {
            "spaceRolesMap": [["S1", "member"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["roles", "arize-nlp-research"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=6, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTpURVNU",
                attr_name="roles", attr_value="arize-nlp-leads",
            )
        ],
        exact_match_uses=[(7, "S1", "member", "")],
    )
    results = [
        _result(6, space="NLP Research", space_role="Testing Custom Roles"),
        _result(7, space="NLP Research", space_role="member", status="already_exists"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    rollback_calls: list[int] = []
    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "NLP Research"},
        results=results,
        logger=logger,
        on_existed_to_error=rollback_calls.append,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    # No errors — both rows keep their original status.
    assert results[0].status == "created"
    assert results[1].status == "already_exists"
    assert not results[0].error_message
    assert not results[1].error_message
    # Existing legacy entry promoted in place.
    assert existing[0]["spaceRolesMap"] == []
    assert existing[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]
    # Matched row 7 got a 'matched' conversion event for the runner to stamp.
    assert (7, "member", "Space Member", "matched") in conversions
    # No rollback fired — the already_exists row keeps its status.
    assert rollback_calls == []


# ── Shape E: matched custom + pending legacy ──────────────────────────────────


def test_shape_e_matched_custom_plus_pending_legacy_converts_pending(
    logger: logging.Logger,
) -> None:
    """6.5: existing custom matched by row N; row M adds legacy on same space.
    Pending legacy is converted; matched custom row is untouched.
    """
    existing = [
        {
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpFWElTVA=="]],
            "attributesMap": [["roles", "existing-custom-group"]],
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=20, org_id="O1", space_id="S1", org_role="member",
                space_role="admin", space_rbac_role_id="",
                attr_name="roles", attr_value="new-legacy-group",
            )
        ],
        exact_match_uses=[(10, "S1", "", "Um9sZTpFWElTVA==")],
    )
    results = [
        _result(10, space_role="Existing Custom", status="already_exists"),
        _result(20, space_role="admin"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: pytest.fail("rollback should not fire"),
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    # Matched custom row 10 stays already_exists, untouched.
    assert results[0].status == "already_exists"
    assert not results[0].note  # no promotion needed on its side
    # Pending legacy row 20 was converted.
    assert results[1].status == "created"
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[20].space_rbac_role_id == "Um9sZTpBRE1JTg=="
    # Existing custom mapping preserved.
    assert existing[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpFWElTVA=="]]
    assert conversions == [(20, "admin", "Space Admin", "pending")]


# ── Failure path: role lookup raises → fall back to error message ────────────


def test_promotion_failure_falls_back_to_error(logger: logging.Logger) -> None:
    """6.6: ensure_legacy_equivalent_role raises → all involved rows get the
    fallback error and pending entries are dropped.
    """
    roles = FakeRoles()
    roles.raise_on = {"admin"}

    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="admin", space_rbac_role_id="",
                attr_name="groups", attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="admin"),
        _result(2, space_role="Project Reviewer"),
    ]
    conversions: list[tuple[int, str, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    assert results[0].status == "error"
    assert results[1].status == "error"
    assert "Auto-promotion" in results[0].error_message
    # Pending entries were dropped so they aren't included in the flush.
    assert saml.pending == ()


# ── Multiple legacy keys on the same conflicted space across mappings ─────────


def test_multiple_legacy_keys_on_same_space_each_get_their_equivalent(
    logger: logging.Logger,
) -> None:
    """6.7: mapping1 has [S1, 'admin']; mapping2 has [S1, 'member']; plus a
    pending custom row on S1. Both legacy keys are converted to their
    respective equivalents."""
    existing = [
        {
            "spaceRolesMap": [["S1", "admin"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "admins"]],
        },
        {
            "spaceRolesMap": [["S1", "member"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "members"]],
        },
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S1", org_role="member",
                space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="custom-users",
            )
        ],
    )
    results = [_result(1, space_role="Project Reviewer")]
    roles = FakeRoles()

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion([]),
    )

    # Both legacy keys looked up.
    assert sorted(roles.calls) == ["admin", "member"]
    # Each existing mapping's [S1, <legacy>] moved to spaceRbacRolesMap with
    # the correct equivalent.
    assert existing[0]["spaceRolesMap"] == []
    assert existing[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert existing[1]["spaceRolesMap"] == []
    assert existing[1]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]


def test_no_conflict_short_circuits(logger: logging.Logger) -> None:
    """When existing + pending touch disjoint spaces, the preflight is a no-op."""
    saml = FakeSaml(
        existing_mappings=[{"spaceRolesMap": [["S1", "admin"]], "spaceRbacRolesMap": []}],
        pending=[
            PendingSAMLMapping(
                row_number=1, org_id="O1", space_id="S2",  # different space
                org_role="member", space_role="", space_rbac_role_id="Um9sZTox",
                attr_name="groups", attr_value="g1",
            )
        ],
    )
    results = [_result(1, space="Other", space_role="Project Reviewer")]

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform", "S2": "Other"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: pytest.fail("rollback should not fire"),
    )

    assert results[0].status == "created"
    assert saml.promote_calls == []
    assert len(saml.pending) == 1
