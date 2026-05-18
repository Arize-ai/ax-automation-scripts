"""Permission sets for auto-creating custom RBAC roles that mirror legacy space roles.

Keys are `PendingSAMLMapping.space_role` values — i.e. the GraphQL form after
`ROLE_ALIAS` translation in [config.py] ("viewer" → "readOnly"). Permission
strings match the proto enum names in proto/auth/protocol/permissions.proto.

Source of truth for the permission sets is
go/pkg/lib/user/user.go lines 216-260 in the main arize repo (as at 2026-05-15):
  - allSpaceReadPermissions   → readOnly
  - allSpaceMemberPermissions → member  (+ serviceKeyPermissions)
  - allSpaceAdminPermissions  → admin   (+ serviceKeyPermissions)

`annotator` has no canonical permission set in the backend (the SpaceAnnotator
case is unimplemented in getAllPermissionsInSpace as of 2026-05-15). We use a
minimal queue-annotate set that matches the UI description "Can only access
assigned labeling queues in assigned spaces".
"""

from __future__ import annotations

# (custom_role_name, description, permissions)
LegacyRoleEquivalent = tuple[str, str, list[str]]

LEGACY_ROLE_EQUIVALENTS: dict[str, LegacyRoleEquivalent] = {
    "admin": (
        "Space Admin",
        "Auto-created by saml_bulk_setup to mirror the legacy Admin space role.",
        [
            # Read across all entities
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            # Model / project admin writes
            "ML_MODEL_CREATE",
            "ML_MODEL_UPDATE",
            "ML_MODEL_DELETE",
            "PROJECT_CREATE",
            "PROJECT_UPDATE",
            "PROJECT_SPAN_CREATE",
            "PROJECT_SPAN_UPDATE",
            "PROJECT_SPAN_ANNOTATE",
            "PROJECT_SPAN_DELETE",
            # Dataset writes
            "DATASET_CREATE",
            "DATASET_UPDATE",
            "DATASET_DELETE",
            "DATASET_EXAMPLE_CREATE",
            "DATASET_EXAMPLE_UPDATE",
            "DATASET_EXAMPLE_DELETE",
            "DATASET_EXAMPLE_ANNOTATE",
            # Experiment writes
            "EXPERIMENT_CREATE",
            "EXPERIMENT_UPDATE",
            "EXPERIMENT_DELETE",
            "EXPERIMENT_RUN_ANNOTATE",
            # Annotation config writes
            "ANNOTATION_CONFIG_CREATE",
            "ANNOTATION_CONFIG_DELETE",
            # Space admin writes
            "SPACE_UPDATE",
            "SPACE_DELETE",
            # Role binding (admin-only)
            "ROLE_BINDING_READ",
            "ROLE_BINDING_CREATE",
            "ROLE_BINDING_DELETE",
            # Queue writes (member + admin sets are identical in the backend)
            "QUEUE_CREATE",
            "QUEUE_UPDATE",
            "QUEUE_DELETE",
            "QUEUE_RECORD_ANNOTATE",
            "QUEUE_RECORD_CREATE",
            "QUEUE_RECORD_UPDATE",
            "QUEUE_RECORD_DELETE",
            # Resource restriction (admin-only)
            "PROJECT_RESTRICT",
            # Service keys (full)
            "SERVICE_KEY_CREATE",
            "SERVICE_KEY_READ",
            "SERVICE_KEY_DELETE",
        ],
    ),
    "member": (
        "Space Member",
        "Auto-created by saml_bulk_setup to mirror the legacy Member space role.",
        [
            # Read across all entities
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            # Model / project member writes (no delete on models/spans)
            "ML_MODEL_CREATE",
            "ML_MODEL_UPDATE",
            "PROJECT_CREATE",
            "PROJECT_UPDATE",
            "PROJECT_SPAN_CREATE",
            "PROJECT_SPAN_UPDATE",
            "PROJECT_SPAN_ANNOTATE",
            # Dataset writes
            "DATASET_CREATE",
            "DATASET_UPDATE",
            "DATASET_DELETE",
            "DATASET_EXAMPLE_CREATE",
            "DATASET_EXAMPLE_UPDATE",
            "DATASET_EXAMPLE_DELETE",
            "DATASET_EXAMPLE_ANNOTATE",
            # Experiment writes
            "EXPERIMENT_CREATE",
            "EXPERIMENT_UPDATE",
            "EXPERIMENT_DELETE",
            "EXPERIMENT_RUN_ANNOTATE",
            # Annotation config writes
            "ANNOTATION_CONFIG_CREATE",
            "ANNOTATION_CONFIG_DELETE",
            # Queue writes
            "QUEUE_CREATE",
            "QUEUE_UPDATE",
            "QUEUE_DELETE",
            "QUEUE_RECORD_ANNOTATE",
            "QUEUE_RECORD_CREATE",
            "QUEUE_RECORD_UPDATE",
            "QUEUE_RECORD_DELETE",
            # Service keys (full)
            "SERVICE_KEY_CREATE",
            "SERVICE_KEY_READ",
            "SERVICE_KEY_DELETE",
        ],
    ),
    "readOnly": (
        "Space Read-Only",
        "Auto-created by saml_bulk_setup to mirror the legacy Member - Read Only space role.",
        [
            "PROJECT_READ",
            "PROJECT_SPAN_READ",
            "ML_MODEL_READ",
            "DATASET_READ",
            "DATASET_EXAMPLE_READ",
            "EXPERIMENT_READ",
            "ANNOTATION_CONFIG_READ",
            "SPACE_READ",
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "SERVICE_KEY_READ",
        ],
    ),
    "annotator": (
        "Space Annotator",
        "Auto-created by saml_bulk_setup to mirror the legacy Annotator space role.",
        [
            "QUEUE_READ",
            "QUEUE_RECORD_READ",
            "QUEUE_RECORD_ANNOTATE",
        ],
    ),
}
