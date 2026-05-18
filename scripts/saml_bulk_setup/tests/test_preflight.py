"""Preflight role-type conflict resolution — covers TEST_SCENARIOS.md section 6.

  6.1 — CSV-internal conflict (two CSV rows, same space, mixed role types)
        → now auto-converts the legacy row(s) to a custom equivalent.
  6.2 — CSV-vs-existing migration: custom CSV row on a space the IdP has under standard
  6.3 — CSV-vs-existing migration: standard CSV row on a space the IdP has under custom
  6.4 — Three-way: already_exists row + new CSV row of opposite type on the same space
        → still errors, since we can't silently mutate an existing exact-match entry.
"""

from __future__ import annotations

import logging

import pytest

from arize_saml_bulk_setup.models import PendingSAMLMapping, RowResult
from arize_saml_bulk_setup.preflight import resolve_role_type_conflicts


class FakeSaml:
    """Stand-in for SamlIdpService that the preflight reads from / mutates.

    Implements only the surface the preflight touches: existing_mappings,
    pending, exact_match_uses, strip_space, drop_pending, pending_row_numbers,
    convert_legacy_to_custom.
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
        self.strip_calls: list[tuple[str, str]] = []
        self.convert_calls: list[tuple[int, str]] = []

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

    def strip_space(self, space_id: str, key: str) -> None:
        self.strip_calls.append((space_id, key))
        for mapping in self._existing:
            if mapping.get(key):
                mapping[key] = [
                    p
                    for p in mapping[key]
                    if not (len(p) >= 2 and p[0] == space_id)
                ]

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


class FakeRoles:
    """Records ensure_legacy_equivalent_role calls and hands back a deterministic relay ID."""

    def __init__(self, mapping: dict[str, tuple[str, str]] | None = None) -> None:
        # legacy_key → (relay_id, custom_name)
        self.mapping = mapping or {
            "admin": ("Um9sZTpBRE1JTg==", "Space Admin"),
            "member": ("Um9sZTpNRU1CRVI=", "Space Member"),
            "readOnly": ("Um9sZTpSRUFE", "Space Read-Only"),
            "annotator": ("Um9sZTpBTk5PVA==", "Space Annotator"),
        }
        self.calls: list[str] = []

    def ensure_legacy_equivalent_role(
        self, legacy_role_key: str
    ) -> tuple[str, str]:
        self.calls.append(legacy_role_key)
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


def _record_conversion(
    sink: list[tuple[int, str, str]],
) -> "callable":
    def _cb(row_number: int, legacy_key: str, custom_name: str) -> None:
        sink.append((row_number, legacy_key, custom_name))

    return _cb


# ── 6.1: CSV-internal conflict (now auto-converts) ───────────────────────────


def test_csv_internal_mix_auto_converts_legacy_to_custom(
    logger: logging.Logger,
) -> None:
    """CSV-internal mix on a space: legacy row is silently converted to custom."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="admin",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="admin"),
        _result(2, space_role="Project Reviewer"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str]] = []

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

    # No errors; both rows keep their original status.
    assert results[0].status == "created"
    assert results[1].status == "created"
    assert not results[0].error_message
    assert not results[1].error_message
    # Pending row 1 was mutated in place to use the relay role ID.
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_role == ""
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTpBRE1JTg=="
    # Pending row 2 untouched.
    assert pending_by_row[2].space_rbac_role_id == "Um9sZTox"
    assert pending_by_row[2].space_role == ""
    # RolesCache was asked exactly once for the admin equivalent.
    assert roles.calls == ["admin"]
    # Runner callback received the conversion event.
    assert conversions == [(1, "admin", "Space Admin")]
    # No already_exists rollbacks fired.
    assert rollback_calls == []


def test_csv_internal_mix_falls_back_to_error_when_roles_not_provided(
    logger: logging.Logger,
) -> None:
    """Backward-compat: when roles is None the preflight still produces errors."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="admin",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g2",
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


def test_auto_conversion_uses_cached_relay_id_when_already_known(
    logger: logging.Logger,
) -> None:
    """A pre-populated FakeRoles mapping is hit on the first call — no second lookup."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="admin",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=3,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="admin",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g3",
            ),
            PendingSAMLMapping(
                row_number=2,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="admin"),
        _result(2, space_role="Project Reviewer"),
        _result(3, space_role="admin"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str]] = []

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
        roles=roles,
        on_legacy_converted=_record_conversion(conversions),
    )

    # Both legacy rows converted; roles was asked twice (cache is the cache's job).
    assert roles.calls == ["admin", "admin"]
    assert {r for r, *_ in conversions} == {1, 3}


def test_annotator_legacy_is_auto_converted(logger: logging.Logger) -> None:
    """Auto-conversion works for all four legacy keys, including annotator."""
    saml = FakeSaml(
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="annotator",
                space_role="annotator",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g1",
            ),
            PendingSAMLMapping(
                row_number=2,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g2",
            ),
        ]
    )
    results = [
        _result(1, space_role="annotator"),
        _result(2, space_role="Project Reviewer"),
    ]
    roles = FakeRoles()
    conversions: list[tuple[int, str, str]] = []

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
    assert conversions == [(1, "annotator", "Space Annotator")]
    pending_by_row = {p.row_number: p for p in saml.pending}
    assert pending_by_row[1].space_rbac_role_id == "Um9sZTpBTk5PVA=="
    assert pending_by_row[1].space_role == ""


# ── 6.2 / 6.3: CSV-vs-existing migration ─────────────────────────────────────


def test_csv_with_custom_role_strips_existing_standard_entry(
    logger: logging.Logger,
) -> None:
    """6.2: IdP has space under spaceRolesMap; CSV asks for a custom role → strip standard."""
    existing = [
        {
            "spaceRolesMap": [["S1", "admin"], ["S2", "member"]],
            "spaceRbacRolesMap": [],
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g1",
            )
        ],
    )
    results = [_result(1, space="ML Platform", space_role="Project Reviewer")]

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform", "S2": "Fraud Detection"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
    )

    # S1 was stripped, S2 preserved
    assert saml.strip_calls == [("S1", "spaceRolesMap")]
    assert existing[0]["spaceRolesMap"] == [["S2", "member"]]
    # Row stays created
    assert results[0].status == "created"


def test_csv_with_standard_role_strips_existing_custom_entry(
    logger: logging.Logger,
) -> None:
    """6.3: IdP has space under spaceRbacRolesMap; CSV asks for builtin → strip custom."""
    existing = [
        {
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTox"]],
        }
    ]
    saml = FakeSaml(
        existing_mappings=existing,
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="admin",
                space_rbac_role_id="",
                attr_name="groups",
                attr_value="g1",
            )
        ],
    )
    results = [_result(1, space_role="admin")]

    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=lambda _row: None,
    )

    assert saml.strip_calls == [("S1", "spaceRbacRolesMap")]
    assert existing[0]["spaceRbacRolesMap"] == []
    assert results[0].status == "created"


# ── 6.4: Three-way (exact-match path) ────────────────────────────────────────


def test_three_way_conflict_via_exact_match_use(logger: logging.Logger) -> None:
    """6.4: an already_exists exact-match row + a new opposite-type pending row on the
    same space still errors. We can't safely mutate an existing IdP entry from this
    code path, so auto-conversion does not apply and the error is preserved.
    """
    saml = FakeSaml(
        existing_mappings=[
            {
                "spaceRolesMap": [["S1", "admin"]],
                "spaceRbacRolesMap": [],
                "attributesMap": [["groups", "g10"]],
                "orgRole": {"orgId": "O1", "roleId": "member"},
            }
        ],
        pending=[
            PendingSAMLMapping(
                row_number=11,
                org_id="O1",
                space_id="S1",
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g11",
            )
        ],
        exact_match_uses=[(10, "S1", "admin", "")],
    )
    results = [
        _result(10, space_role="admin", status="already_exists"),
        _result(11, space_role="Project Reviewer", status="created"),
    ]
    roles = FakeRoles()

    rollback_calls: list[int] = []
    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=rollback_calls.append,
        roles=roles,
        on_legacy_converted=lambda *_args: None,
    )

    assert results[0].status == "error"
    assert results[1].status == "error"
    # Only the already_exists row triggers a rollback
    assert rollback_calls == [10]
    # Auto-conversion was NOT attempted (the legacy row isn't pending).
    assert roles.calls == []
    assert saml.convert_calls == []


def test_no_conflict_short_circuits(logger: logging.Logger) -> None:
    """When existing + pending touch disjoint spaces, the preflight is a no-op."""
    saml = FakeSaml(
        existing_mappings=[{"spaceRolesMap": [["S1", "admin"]], "spaceRbacRolesMap": []}],
        pending=[
            PendingSAMLMapping(
                row_number=1,
                org_id="O1",
                space_id="S2",  # different space
                org_role="member",
                space_role="",
                space_rbac_role_id="Um9sZTox",
                attr_name="groups",
                attr_value="g1",
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
    assert saml.strip_calls == []
    assert len(saml.pending) == 1
