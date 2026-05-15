"""Preflight role-type conflict resolution — covers TEST_SCENARIOS.md section 6.

  6.1 — CSV-internal conflict (two CSV rows, same space, mixed role types)
  6.2 — CSV-vs-existing migration: custom CSV row on a space the IdP has under standard
  6.3 — CSV-vs-existing migration: standard CSV row on a space the IdP has under custom
  6.4 — Three-way: already_exists row + new CSV row of opposite type on the same space
"""

from __future__ import annotations

import logging

import pytest

from arize_saml_bulk_setup.models import PendingSAMLMapping, RowResult
from arize_saml_bulk_setup.preflight import resolve_role_type_conflicts


class FakeSaml:
    """Stand-in for SamlIdpService that the preflight reads from / mutates.

    Implements only the surface the preflight touches: existing_mappings,
    pending, exact_match_uses, strip_space, drop_pending.
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


# ── 6.1: CSV-internal conflict ───────────────────────────────────────────────


def test_csv_internal_conflict_errors_both_rows(logger: logging.Logger) -> None:
    """Two CSV rows on the same space — one builtin, one custom — both fail."""
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

    rollback_calls: list[int] = []
    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=rollback_calls.append,
    )

    assert results[0].status == "error"
    assert results[1].status == "error"
    assert "row 1 ('admin')" in results[0].error_message
    assert "row 2 ('Project Reviewer')" in results[0].error_message
    assert saml.pending == ()
    # No rows were previously already_exists, so no rollback fires
    assert rollback_calls == []


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
    """6.4: a row marked already_exists for one role-type + a new row of the other type
    on the same space → both rows error and the already_exists row's counter rolls back."""
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

    rollback_calls: list[int] = []
    resolve_role_type_conflicts(
        saml=saml,
        space_id_to_name={"S1": "ML Platform"},
        results=results,
        logger=logger,
        on_existed_to_error=rollback_calls.append,
    )

    assert results[0].status == "error"
    assert results[1].status == "error"
    # Only the already_exists row triggers a rollback
    assert rollback_calls == [10]


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
