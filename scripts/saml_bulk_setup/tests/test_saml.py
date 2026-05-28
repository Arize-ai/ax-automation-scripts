"""SamlIdpService — covers TEST_SCENARIOS.md section 7 (7.1–7.7)."""

from __future__ import annotations

import logging

import pytest

from arize_saml_bulk_setup.models import PendingSAMLMapping
from arize_saml_bulk_setup.saml import SamlIdpService


def _saml(
    fake_executor,
    logger: logging.Logger,
    *,
    dry_run: bool = False,
    saml_metadata_url: str | None = None,
    saml_metadata_xml: str | None = None,
    email_domains: list[str] | None = None,
    enforce_saml: bool | None = None,
    sync_user_roles: bool | None = None,
    sign_authn: bool | None = None,
) -> SamlIdpService:
    return SamlIdpService(
        execute_graphql=fake_executor,
        logger=logger,
        dry_run=dry_run,
        saml_metadata_url=saml_metadata_url,
        saml_metadata_xml=saml_metadata_xml,
        email_domains=email_domains,
        enforce_saml=enforce_saml,
        sync_user_roles=sync_user_roles,
        sign_authn=sign_authn,
    )


# ── 7.1–7.4: IdP creation path ───────────────────────────────────────────────


def test_no_idp_and_no_metadata_raises_with_guidance(
    fake_executor, logger: logging.Logger
) -> None:
    """7.1: missing both --email-domains and metadata → clear error from ensure_loaded."""
    fake_executor.responses["getSAMLIdP"] = {"account": {"samlIdPs": {"edges": []}}}
    saml = _saml(fake_executor, logger)
    with pytest.raises(RuntimeError, match="No SAML IdP found for this account"):
        saml.ensure_loaded()


def test_no_idp_with_email_only_raises(
    fake_executor, logger: logging.Logger
) -> None:
    """7.2: providing email-domains without metadata is still rejected."""
    fake_executor.responses["getSAMLIdP"] = {"account": {"samlIdPs": {"edges": []}}}
    saml = _saml(fake_executor, logger, email_domains=["acme.com"])
    with pytest.raises(RuntimeError, match="no metadata supplied"):
        saml.ensure_loaded()


def test_no_idp_with_metadata_url_creates_on_flush(
    fake_executor, logger: logging.Logger
) -> None:
    """7.3: createSAMLIdP receives the URL + all pending mappings."""
    fake_executor.responses["getSAMLIdP"] = {"account": {"samlIdPs": {"edges": []}}}
    fake_executor.responses["createSAMLIdP"] = {
        "createSAMLIdP": {
            "idp": {"id": "Idp_new", "roleMappings": []},
            "error": None,
        }
    }
    saml = _saml(
        fake_executor,
        logger,
        saml_metadata_url="https://idp.example.com/metadata",
        email_domains=["acme.com"],
    )
    saml.ensure_loaded()
    saml.queue_mapping(
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
    )
    saml.flush()

    # The last call should be createSAMLIdP with our URL + mapping
    create_calls = [c for c in fake_executor.calls if c[0] == "createSAMLIdP"]
    assert len(create_calls) == 1
    payload = create_calls[0][1]["input"]
    assert payload["metadataUrl"] == "https://idp.example.com/metadata"
    assert payload["emailDomainsList"] == [{"domain": "acme.com"}]
    assert len(payload["roleMappings"]["mappingsList"]) == 1
    assert payload["roleMappings"]["mappingsList"][0]["spaceRolesMap"] == [
        ["S1", "admin"]
    ]


def test_no_idp_with_metadata_xml_uses_xml_field(
    fake_executor, logger: logging.Logger
) -> None:
    """7.4: --saml-metadata-xml routes into metadataXml on the create input."""
    fake_executor.responses["getSAMLIdP"] = {"account": {"samlIdPs": {"edges": []}}}
    fake_executor.responses["createSAMLIdP"] = {
        "createSAMLIdP": {"idp": {"id": "Idp_x", "roleMappings": []}, "error": None}
    }
    saml = _saml(
        fake_executor,
        logger,
        saml_metadata_xml="<EntityDescriptor>...</EntityDescriptor>",
        email_domains=["acme.com"],
    )
    saml.ensure_loaded()
    saml.queue_mapping(
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
    )
    saml.flush()
    payload = fake_executor.calls[-1][1]["input"]
    assert payload["metadataXml"] == "<EntityDescriptor>...</EntityDescriptor>"
    assert "metadataUrl" not in payload
    # Custom RBAC entry routed to spaceRbacRolesMap, not spaceRolesMap
    mapping = payload["roleMappings"]["mappingsList"][0]
    assert mapping["spaceRbacRolesMap"] == [["S1", "Um9sZTox"]]
    assert "spaceRolesMap" not in mapping


# ── 7.5–7.7: SAML flag flips on existing IdP ─────────────────────────────────


def _existing_idp_response(
    *,
    enforce: bool = False,
    sync: bool = False,
    sign: bool = False,
    allow_defaults: bool = False,
    email_domains: list[str] | None = None,
) -> dict:
    return {
        "account": {
            "samlIdPs": {
                "edges": [
                    {
                        "node": {
                            "id": "Idp_existing",
                            "emailDomainsList": [
                                {"domain": d} for d in (email_domains or ["acme.com"])
                            ],
                            "enforceSaml": enforce,
                            "syncUserRoles": sync,
                            "signAuthn": sign,
                            "allowLoginWithDefaults": allow_defaults,
                            "roleMappings": [],
                        }
                    }
                ]
            }
        }
    }


def test_enforce_saml_flag_flips_on_existing_idp(
    fake_executor, logger: logging.Logger
) -> None:
    """7.5: --enforce-saml on an existing IdP with enforceSaml=False → flips to True on update."""
    fake_executor.responses["getSAMLIdP"] = _existing_idp_response(enforce=False)
    fake_executor.responses["updateSAMLIdP"] = {
        "updateSAMLIdP": {"idp": {"id": "Idp_existing", "roleMappings": []}, "error": None}
    }
    saml = _saml(fake_executor, logger, enforce_saml=True)
    saml.ensure_loaded()
    saml.queue_mapping(
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
    )
    saml.flush()

    update = fake_executor.calls[-1]
    assert update[0] == "updateSAMLIdP"
    assert update[1]["input"]["enforceSaml"] is True


@pytest.mark.parametrize(
    "ctor_kwargs,flag_key,expected",
    [
        ({"sync_user_roles": True}, "syncUserRoles", True),
        ({"sign_authn": True}, "signAuthn", True),
    ],
    ids=["sync-user-roles", "sign-authn"],
)
def test_other_flag_flips_on_existing_idp(
    fake_executor, logger: logging.Logger, ctor_kwargs, flag_key, expected
) -> None:
    """7.6: --sync-user-roles and --sign-authn flip the same way."""
    fake_executor.responses["getSAMLIdP"] = _existing_idp_response()
    fake_executor.responses["updateSAMLIdP"] = {
        "updateSAMLIdP": {"idp": {"id": "X", "roleMappings": []}, "error": None}
    }
    saml = _saml(fake_executor, logger, **ctor_kwargs)
    saml.ensure_loaded()
    saml.queue_mapping(
        PendingSAMLMapping(
            row_number=1, org_id="O1", space_id="S1", org_role="member",
            space_role="admin", space_rbac_role_id="",
            attr_name="groups", attr_value="g1",
        )
    )
    saml.flush()
    assert fake_executor.calls[-1][1]["input"][flag_key] is expected


def test_existing_flag_values_preserved_when_no_flag_passed(
    fake_executor, logger: logging.Logger
) -> None:
    """7.7: no flag passed → existing enforceSaml=True stays True after update."""
    fake_executor.responses["getSAMLIdP"] = _existing_idp_response(
        enforce=True, sync=True, sign=False
    )
    fake_executor.responses["updateSAMLIdP"] = {
        "updateSAMLIdP": {"idp": {"id": "X", "roleMappings": []}, "error": None}
    }
    saml = _saml(
        fake_executor,
        logger,
        enforce_saml=None,
        sync_user_roles=None,
        sign_authn=None,
    )
    saml.ensure_loaded()
    saml.queue_mapping(
        PendingSAMLMapping(
            row_number=1, org_id="O1", space_id="S1", org_role="member",
            space_role="admin", space_rbac_role_id="",
            attr_name="groups", attr_value="g1",
        )
    )
    saml.flush()
    payload = fake_executor.calls[-1][1]["input"]
    assert payload["enforceSaml"] is True  # preserved
    assert payload["syncUserRoles"] is True  # preserved
    assert payload["signAuthn"] is False  # preserved


# ── mapping_exists invariants ────────────────────────────────────────────────


def test_mapping_exists_dedupes_within_pending(
    fake_executor, logger: logging.Logger
) -> None:
    """Even with no IdP, two identical pending mappings should dedupe."""
    fake_executor.responses["getSAMLIdP"] = {"account": {"samlIdPs": {"edges": []}}}
    saml = _saml(
        fake_executor, logger,
        email_domains=["acme.com"],
        saml_metadata_url="https://idp.example.com/m",
    )
    saml.ensure_loaded()
    saml.queue_mapping(
        PendingSAMLMapping(
            row_number=1, org_id="O1", space_id="S1", org_role="member",
            space_role="admin", space_rbac_role_id="",
            attr_name="groups", attr_value="g1",
        )
    )
    assert saml.mapping_exists(
        space_id="S1",
        org_role="member",
        space_role="admin",
        space_rbac_role_id="",
        attr_name="groups",
        attr_value="g1",
    )


def test_mapping_exists_matches_existing_inherited_entry(
    fake_executor, logger: logging.Logger
) -> None:
    """A mapping with no space role (inherited) is identified by attr+org_role alone."""
    fake_executor.responses["getSAMLIdP"] = {
        "account": {
            "samlIdPs": {
                "edges": [
                    {
                        "node": {
                            "id": "Idp_x",
                            "emailDomainsList": [{"domain": "acme.com"}],
                            "enforceSaml": False,
                            "syncUserRoles": True,
                            "signAuthn": False,
                            "allowLoginWithDefaults": False,
                            "roleMappings": [
                                {
                                    "id": "RM1",
                                    "attributesMap": [["groups", "g1"]],
                                    "spaceRolesMap": [],
                                    "spaceRbacRolesMap": [],
                                    "isAccountAdmin": False,
                                    "orgRole": {"orgId": "O1", "roleId": "member"},
                                }
                            ],
                        }
                    }
                ]
            }
        }
    }
    saml = _saml(fake_executor, logger)
    saml.ensure_loaded()
    assert saml.mapping_exists(
        space_id="S1",  # ignored for inherited
        org_role="member",
        space_role="",
        space_rbac_role_id="",
        attr_name="groups",
        attr_value="g1",
    )


# ── promote_existing_legacy_for_space ────────────────────────────────────────


class _FakeRolesForPromotion:
    """Minimal RolesCache stand-in for promote_existing_legacy_for_space tests."""

    def __init__(self) -> None:
        self.mapping = {
            "admin": ("Um9sZTpBRE1JTg==", "Space Admin"),
            "member": ("Um9sZTpNRU1CRVI=", "Space Member"),
            "readOnly": ("Um9sZTpSRUFE", "Space Read-Only"),
            "annotator": ("Um9sZTpBTk5PVA==", "Space Annotator"),
        }
        self.calls: list[str] = []

    def ensure_legacy_equivalent_role(self, legacy_key: str) -> tuple[str, str]:
        self.calls.append(legacy_key)
        return self.mapping[legacy_key]


def _saml_with_existing(
    fake_executor, logger: logging.Logger, mappings: list[dict]
):
    """Helper: build a SamlIdpService and seed it with the given existing mappings.

    Avoids the full ensure_loaded → GraphQL round-trip; we only need the
    `_existing_mappings` list populated for these tests.
    """
    saml = _saml(fake_executor, logger)
    saml._existing_mappings = mappings  # noqa: SLF001 — test-only seam
    saml._idp_id = "Idp_existing"  # noqa: SLF001
    return saml


def test_promote_existing_legacy_single_mapping(
    fake_executor, logger: logging.Logger
) -> None:
    """Single mapping with one legacy entry for the space — pair moved to RBAC."""
    mappings = [
        {
            "spaceRolesMap": [["S1", "member"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "g1"]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    roles = _FakeRolesForPromotion()

    conversions = saml.promote_existing_legacy_for_space("S1", roles)

    assert mappings[0]["spaceRolesMap"] == []
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]
    assert conversions == [("member", "Space Member")]
    assert roles.calls == ["member"]


def test_promote_existing_legacy_idempotent(
    fake_executor, logger: logging.Logger
) -> None:
    """A second call on the same space finds nothing to promote — no further mutation, no role lookup."""
    mappings = [
        {
            "spaceRolesMap": [["S1", "admin"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "g1"]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    roles = _FakeRolesForPromotion()

    saml.promote_existing_legacy_for_space("S1", roles)
    saml.promote_existing_legacy_for_space("S1", roles)  # second call

    # spaceRbacRolesMap doesn't double up; spaceRolesMap stays empty.
    assert mappings[0]["spaceRolesMap"] == []
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    # The role was looked up only once across the two calls (second pass had
    # nothing to convert, so ensure_legacy_equivalent_role wasn't called).
    assert roles.calls == ["admin"]


def test_promote_existing_legacy_preserves_other_spaces(
    fake_executor, logger: logging.Logger
) -> None:
    """Other spaces on the same mapping are not touched."""
    mappings = [
        {
            "spaceRolesMap": [["S1", "member"], ["S2", "admin"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "g1"]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    roles = _FakeRolesForPromotion()

    saml.promote_existing_legacy_for_space("S1", roles)

    assert mappings[0]["spaceRolesMap"] == [["S2", "admin"]]
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]


def test_promote_existing_legacy_across_multiple_mappings(
    fake_executor, logger: logging.Logger
) -> None:
    """The same space referenced from multiple mappings is fully converted."""
    mappings = [
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
    saml = _saml_with_existing(fake_executor, logger, mappings)
    roles = _FakeRolesForPromotion()

    conversions = saml.promote_existing_legacy_for_space("S1", roles)

    assert mappings[0]["spaceRolesMap"] == []
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert mappings[1]["spaceRolesMap"] == []
    assert mappings[1]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]
    # Returned conversions dedup keys across mappings.
    assert set(conversions) == {("admin", "Space Admin"), ("member", "Space Member")}
    assert sorted(roles.calls) == ["admin", "member"]


def test_promote_existing_legacy_no_match_is_noop(
    fake_executor, logger: logging.Logger
) -> None:
    """Promoting a space that's not in any existing mapping is a no-op."""
    mappings = [
        {
            "spaceRolesMap": [["S2", "admin"]],
            "spaceRbacRolesMap": [],
            "attributesMap": [["groups", "g1"]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    roles = _FakeRolesForPromotion()

    conversions = saml.promote_existing_legacy_for_space("S1", roles)

    assert conversions == []
    assert roles.calls == []
    # S2 untouched
    assert mappings[0]["spaceRolesMap"] == [["S2", "admin"]]


# ── reconcile_pending_into_existing ──────────────────────────────────────────


def _capture_absorbed():
    """Return (sink, callback) for assertions on absorbed events."""
    sink: list[tuple[int, str, str, str, str]] = []

    def _cb(row_number, kind, attr_name, attr_value, prior_role_label):
        sink.append((row_number, kind, attr_name, attr_value, prior_role_label))

    return sink, _cb


def _make_pending(
    row_number: int,
    *,
    space_id: str = "S1",
    space_role: str = "",
    space_rbac_role_id: str = "",
    attr_name: str = "roles",
    attr_value: str = "g1",
    org_role: str = "member",
    org_id: str = "O1",
) -> PendingSAMLMapping:
    return PendingSAMLMapping(
        row_number=row_number,
        org_id=org_id,
        space_id=space_id,
        org_role=org_role,
        space_role=space_role,
        space_rbac_role_id=space_rbac_role_id,
        attr_name=attr_name,
        attr_value=attr_value,
    )


def test_reconcile_idempotent_drops_pending_when_existing_has_same_rbac_role(
    fake_executor, logger: logging.Logger
) -> None:
    """Case 2: existing has [S1, RoleX] in spaceRbacRolesMap; pending matches exactly."""
    mappings = [
        {
            "attributesMap": [["roles", "engineers"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpNRU1CRVI="]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [
        _make_pending(
            row_number=1,
            space_id="S1",
            space_rbac_role_id="Um9sZTpNRU1CRVI=",
            attr_value="engineers",
        )
    ]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    assert saml.pending == ()  # dropped
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpNRU1CRVI="]]
    assert sink == [(1, "idempotent", "roles", "engineers", "")]


def test_reconcile_replace_swaps_role_in_existing(
    fake_executor, logger: logging.Logger
) -> None:
    """Case 3: existing has [S1, OldRole]; pending wants [S1, NewRole] (same map)."""
    mappings = [
        {
            "attributesMap": [["roles", "leads"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpURVNUSU5H"]],  # Testing Custom Role
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [
        _make_pending(
            row_number=2,
            space_id="S1",
            space_rbac_role_id="Um9sZTpBRE1JTg==",  # Space Admin
            attr_value="leads",
        )
    ]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    assert saml.pending == ()
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert sink == [(2, "replaced", "roles", "leads", "Um9sZTpURVNUSU5H")]


def test_reconcile_replace_handles_opposite_map(
    fake_executor, logger: logging.Logger
) -> None:
    """Existing has [S1, legacy-role]; pending wants [S1, custom-role] → swap maps."""
    mappings = [
        {
            "attributesMap": [["roles", "leads"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [["S1", "admin"]],
            "spaceRbacRolesMap": [],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [
        _make_pending(
            row_number=3,
            space_id="S1",
            space_rbac_role_id="Um9sZTpBRE1JTg==",
            attr_value="leads",
        )
    ]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    assert saml.pending == ()
    assert mappings[0]["spaceRolesMap"] == []
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert sink == [(3, "replaced", "roles", "leads", "admin")]


def test_reconcile_extended_appends_new_space_to_existing(
    fake_executor, logger: logging.Logger
) -> None:
    """Case 4: existing has [S1, RoleX]; pending adds [S2, RoleY] under same attrs."""
    mappings = [
        {
            "attributesMap": [["roles", "foo"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpNRU1CRVI="]],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [
        _make_pending(
            row_number=4,
            space_id="S2",
            space_rbac_role_id="Um9sZTpBRE1JTg==",
            attr_value="foo",
        )
    ]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    assert saml.pending == ()
    assert mappings[0]["spaceRbacRolesMap"] == [
        ["S1", "Um9sZTpNRU1CRVI="],
        ["S2", "Um9sZTpBRE1JTg=="],
    ]
    assert sink == [(4, "extended", "roles", "foo", "")]


def test_reconcile_inherited_pending_drops_when_existing_matches(
    fake_executor, logger: logging.Logger
) -> None:
    """Case 5: pending with no role fields matches existing's (attr, val, org_role)."""
    mappings = [
        {
            "attributesMap": [["roles", "all-users"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [_make_pending(row_number=5, attr_value="all-users")]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    assert saml.pending == ()
    assert sink == [(5, "inherited", "roles", "all-users", "")]


def test_reconcile_no_match_keeps_pending(
    fake_executor, logger: logging.Logger
) -> None:
    """Case 1: pending references an attribute pair the IdP doesn't have."""
    mappings = [
        {
            "attributesMap": [["roles", "other"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [],
        }
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    pending = _make_pending(
        row_number=6, space_id="S1", space_rbac_role_id="Um9sZTpBRE1JTg==",
        attr_value="new-group",
    )
    saml._pending = [pending]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    # Pending preserved, no callback fired
    assert len(saml.pending) == 1
    assert saml.pending[0] is pending
    assert sink == []


def test_reconcile_picks_first_match_when_multiple(
    fake_executor, logger: logging.Logger
) -> None:
    """Defensive: if multiple existing mappings share (attr, val, org_role), use the first."""
    mappings = [
        {
            "attributesMap": [["roles", "dup"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpNRU1CRVI="]],
        },
        {
            "attributesMap": [["roles", "dup"]],
            "orgRole": {"orgId": "O1", "roleId": "member"},
            "spaceRolesMap": [],
            "spaceRbacRolesMap": [["S1", "Um9sZTpBRE1JTg=="]],
        },
    ]
    saml = _saml_with_existing(fake_executor, logger, mappings)
    saml._pending = [
        _make_pending(
            row_number=7, space_id="S1",
            space_rbac_role_id="Um9sZTpOWldX",
            attr_value="dup",
        )
    ]
    sink, cb = _capture_absorbed()

    saml.reconcile_pending_into_existing(on_absorbed=cb)

    # First mapping mutated; second untouched.
    assert mappings[0]["spaceRbacRolesMap"] == [["S1", "Um9sZTpOWldX"]]
    assert mappings[1]["spaceRbacRolesMap"] == [["S1", "Um9sZTpBRE1JTg=="]]
    assert sink == [(7, "replaced", "roles", "dup", "Um9sZTpNRU1CRVI=")]


# ── collapse_pending_by_attributes ───────────────────────────────────────────


def test_collapse_groups_pending_with_same_attr_val_org_role(
    fake_executor, logger: logging.Logger
) -> None:
    """Three pending entries on the same (attr, val, org_role) collapse to one."""
    saml = _saml_with_existing(fake_executor, logger, [])
    saml._pending = [
        _make_pending(
            row_number=1, space_id="S1",
            space_rbac_role_id="Um9sZTpB", attr_value="foo",
        ),
        _make_pending(
            row_number=2, space_id="S2",
            space_rbac_role_id="Um9sZTpC", attr_value="foo",
        ),
        _make_pending(
            row_number=3, space_id="S3",
            space_role="admin", attr_value="foo",
        ),
    ]
    merged: list[tuple[int, int, str, str]] = []
    saml.collapse_pending_by_attributes(
        on_merged=lambda rn, owner, an, av: merged.append((rn, owner, an, av))
    )

    # One survivor (row 1), with extras for the other two.
    assert len(saml.pending) == 1
    owner = saml.pending[0]
    assert owner.row_number == 1
    assert owner.extra_space_rbac_pairs == [("S2", "Um9sZTpC")]
    assert owner.extra_space_legacy_pairs == [("S3", "admin")]
    assert merged == [
        (2, 1, "roles", "foo"),
        (3, 1, "roles", "foo"),
    ]


def test_collapse_leaves_distinct_attr_pairs_alone(
    fake_executor, logger: logging.Logger
) -> None:
    saml = _saml_with_existing(fake_executor, logger, [])
    saml._pending = [
        _make_pending(row_number=1, attr_value="foo", space_rbac_role_id="R1"),
        _make_pending(row_number=2, attr_value="bar", space_rbac_role_id="R2"),
    ]
    merged: list[tuple[int, int, str, str]] = []
    saml.collapse_pending_by_attributes(
        on_merged=lambda *_args: merged.append(_args)
    )

    assert len(saml.pending) == 2
    assert merged == []


# ── _build_new_mappings_input with extra pairs ───────────────────────────────


def test_build_new_mappings_emits_extra_rbac_pairs(
    fake_executor, logger: logging.Logger
) -> None:
    """A pending with extra_space_rbac_pairs serializes to one entry with all pairs."""
    saml = _saml_with_existing(fake_executor, logger, [])
    owner = _make_pending(
        row_number=1, space_id="S1",
        space_rbac_role_id="R1", attr_value="foo",
    )
    owner.extra_space_rbac_pairs = [("S2", "R2")]
    saml._pending = [owner]

    entries = saml._build_new_mappings_input()

    assert len(entries) == 1
    assert entries[0]["spaceRbacRolesMap"] == [["S1", "R1"], ["S2", "R2"]]
    assert "spaceRolesMap" not in entries[0]


def test_build_new_mappings_emits_mixed_legacy_and_rbac_pairs(
    fake_executor, logger: logging.Logger
) -> None:
    """An owner with both rbac primary + extra legacy emits both maps."""
    saml = _saml_with_existing(fake_executor, logger, [])
    owner = _make_pending(
        row_number=1, space_id="S1",
        space_rbac_role_id="R1", attr_value="foo",
    )
    owner.extra_space_legacy_pairs = [("S3", "admin")]
    saml._pending = [owner]

    entries = saml._build_new_mappings_input()

    assert entries[0]["spaceRbacRolesMap"] == [["S1", "R1"]]
    assert entries[0]["spaceRolesMap"] == [["S3", "admin"]]
