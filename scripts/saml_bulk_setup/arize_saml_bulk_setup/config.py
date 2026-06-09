"""Constants and lookup tables shared across the package."""

from __future__ import annotations

ARIZE_APP_URL = "https://app.arize.com"
ARIZE_REST_API_URL = "https://api.arize.com"

MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

# Base64 prefix for relay global IDs of the form "Role:<int>".
RELAY_ROLE_ID_PREFIX = "Um9sZTo"

# CSV accepts "viewer" as a human-friendly alias; Arize GraphQL uses "readOnly".
ROLE_ALIAS: dict[str, str] = {
    "admin": "admin",
    "member": "member",
    "viewer": "readOnly",
    "annotator": "annotator",
}

VALID_ORG_ROLES: set[str] = set(ROLE_ALIAS.keys())

REQUIRED_COLUMNS: set[str] = {
    "organization",
    "space",
    "arize_org_role",
    "arize_space_role",
    "saml_attribute_name",
    "saml_attribute_value",
}

OUTPUT_COLUMNS: list[str] = [
    "organization",
    "space",
    "arize_org_role",
    "arize_space_role",
    "saml_attribute_name",
    "saml_attribute_value",
    "status",
    "error_message",
    "note",
]

# Project-assignment feature (--project-assign flag).
# These columns are optional in the CSV; only read when the flag is active.
PROJECT_COLUMNS: tuple[str, ...] = ("project", "project_emails")

# When --project-assign is set, the output CSV includes two extra columns.
OUTPUT_COLUMNS_WITH_PROJECTS: list[str] = [
    "organization",
    "space",
    "arize_org_role",
    "arize_space_role",
    "saml_attribute_name",
    "saml_attribute_value",
    "project",
    "project_emails",
    "status",
    "error_message",
    "note",
]

# invite_mode=none: creates a user with SSO-only access and no email invite.
# Role bindings require an existing user_id, so users that haven't logged in
# via SAML yet must be pre-created this way.
PROJECT_INVITE_MODE = "none"
