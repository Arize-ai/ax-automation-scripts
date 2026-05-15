"""Constants and lookup tables shared across the package."""

from __future__ import annotations

ARIZE_APP_URL = "https://app.arize.com"
ARIZE_REST_API_URL = "https://api.arize.com"

MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

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
]
