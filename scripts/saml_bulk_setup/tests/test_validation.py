"""Per-row validation — covers TEST_SCENARIOS.md section 2 (scenarios 2.1–2.6)."""

from __future__ import annotations

import pytest

from arize_saml_bulk_setup.runner import _classify_space_role, _validate_row


# ── _validate_row ────────────────────────────────────────────────────────────


def test_valid_row_returns_empty_error() -> None:
    err = _validate_row(
        org_name="Acme",
        space_name="S",
        arize_org_role="member",
        arize_space_role_raw="admin",
        attr_name="groups",
        attr_value="g1",
    )
    assert err == ""


@pytest.mark.parametrize(
    "field_to_blank,expected_in_message",
    [
        ("org_name", "organization"),
        ("space_name", "space"),
        ("arize_org_role", "arize_org_role"),
        ("attr_name", "saml_attribute_name"),
        ("attr_value", "saml_attribute_value"),
    ],
    ids=["org", "space", "org_role", "attr_name", "attr_value"],
)
def test_missing_required_field_is_reported(
    field_to_blank: str, expected_in_message: str
) -> None:
    """2.1: each required field, blanked, surfaces in the error message."""
    args = dict(
        org_name="Acme",
        space_name="S",
        arize_org_role="member",
        arize_space_role_raw="",
        attr_name="groups",
        attr_value="g1",
    )
    args[field_to_blank] = ""
    err = _validate_row(**args)
    assert "Missing required field(s)" in err
    assert expected_in_message in err


@pytest.mark.parametrize("bad_role", ["owner", "reader", "guest", "supervisor"])
def test_invalid_org_role_is_reported(bad_role: str) -> None:
    """2.2: org_role outside {admin, member, viewer, annotator} fails.

    `_validate_row`'s contract assumes the caller has already stripped and
    lowercased the value (which process_row does), so we test with the
    normalized form.
    """
    err = _validate_row(
        org_name="Acme",
        space_name="S",
        arize_org_role=bad_role,
        arize_space_role_raw="",
        attr_name="groups",
        attr_value="g1",
    )
    assert "Invalid arize_org_role" in err
    assert "admin, annotator, member, viewer" in err


@pytest.mark.parametrize("space_role", ["admin", "member", "viewer", "Custom Role"])
def test_admin_with_any_space_role_fails(space_role: str) -> None:
    """2.3: org admin + non-empty space role is rejected."""
    err = _validate_row(
        org_name="Acme",
        space_name="S",
        arize_org_role="admin",
        arize_space_role_raw=space_role,
        attr_name="groups",
        attr_value="g1",
    )
    assert "Invalid combination" in err
    assert "admin" in err
    assert space_role in err


def test_admin_with_blank_space_role_passes() -> None:
    err = _validate_row(
        org_name="Acme",
        space_name="S",
        arize_org_role="admin",
        arize_space_role_raw="",
        attr_name="groups",
        attr_value="g1",
    )
    assert err == ""


# ── _classify_space_role ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected_role,expected_is_custom",
    [
        ("", "", False),  # 2.5 — blank inherits
        ("admin", "admin", False),  # 2.4 — builtin alias
        ("ADMIN", "admin", False),
        ("member", "member", False),
        ("viewer", "readOnly", False),  # 2.4 — viewer translates to readOnly
        ("VIEWER", "readOnly", False),
        ("annotator", "annotator", False),
        ("Project Reviewer", "", True),  # 2.6 — custom role
        ("ml-eng", "", True),
    ],
    ids=[
        "blank-inherits",
        "admin",
        "admin-upper",
        "member",
        "viewer-translated-to-readOnly",
        "viewer-upper",
        "annotator",
        "custom-role-name",
        "custom-with-hyphen",
    ],
)
def test_classify_space_role(
    raw: str, expected_role: str, expected_is_custom: bool
) -> None:
    role, is_custom = _classify_space_role(raw)
    assert role == expected_role
    assert is_custom is expected_is_custom
