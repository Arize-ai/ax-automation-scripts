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
