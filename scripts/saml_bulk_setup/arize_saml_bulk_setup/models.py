"""Plain-data structures passed between services."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RowResult:
    """One row's outcome.

    `status` is one of: "created", "already_exists", "dry_run", "error".
    `error_message` is non-empty only when `status == "error"`.
    `note` is a non-error advisory (e.g. legacy→custom auto-conversion) shown
    in the results CSV alongside non-error statuses.
    """

    row_number: int
    organization: str
    space: str
    arize_org_role: str
    arize_space_role: str
    saml_attribute_name: str
    saml_attribute_value: str
    status: str = ""
    error_message: str = ""
    note: str = ""


@dataclass
class PendingSAMLMapping:
    """A new SAML role mapping queued for creation, tied back to a CSV row.

    The primary `(space_id, space_role|space_rbac_role_id)` pair represents
    the row that originated this entry. `extra_space_*_pairs` carry additional
    space-role pairs folded in from sibling rows that share the same
    `(attr_name, attr_value, org_role)`; they're emitted together as a single
    mapping at flush time.
    """

    row_number: int
    org_id: str
    space_id: str
    org_role: str  # translated: "admin" | "member" | "readOnly" | "annotator"
    # Exactly one of space_role / space_rbac_role_id is set (or both empty,
    # meaning inherit the space role from the org role).
    space_role: str  # legacy builtin: "admin" | "member" | "readOnly" | "annotator"
    space_rbac_role_id: str  # custom RBAC role relay global ID (e.g. "Um9sZTo...")
    attr_name: str
    attr_value: str
    # Filled in by SamlIdpService._collapse_pending_by_attributes when sibling
    # rows are merged into this owner entry.
    extra_space_rbac_pairs: list[tuple[str, str]] = field(default_factory=list)
    extra_space_legacy_pairs: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class SamlFlags:
    """SAML config flags used for create defaults and update preservation."""

    enforce_saml: bool
    sync_user_roles: bool
    sign_authn: bool
    allow_login_with_defaults: bool
