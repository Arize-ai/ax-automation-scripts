"""Tests for ProjectService and the --project-assign runner path.

Coverage:
  Unit (ProjectService):
    P1  resolve_project — create new project
    P2  resolve_project — already exists (cache hit from list)
    P3  restrict_project — success
    P4  restrict_project — already restricted (idempotent)
    P5  restrict_project — dry-run skips API call
    P6  resolve_user — existing user returned from list
    P7  resolve_user — auto-create new user with correct org role
    P8  resolve_user — 409 race recovered via cache reload
    P9  assign_user_to_project — granted
    P10 assign_user_to_project — 409 already granted (idempotent)
    P11 assign_user_to_project — dry-run skips API call

  Runner integration (--project-assign):
    R1  project_assign=False → project columns ignored even if present in CSV
    R2  project_assign=True, row has no project → no project phase
    R3  project_assign=True, role not in account → row error from resolve_custom_space_role
    R4  project_assign=True, project set but project_emails empty → row error
    R5  project_assign=True, happy path → project created, restricted, users assigned
    R6  project_assign=True, dry-run → dry_run status, no API writes
    R7  project_assign=True, idempotent — already_exists + already_granted notes
    R8  project counter deduplication — same project on two rows counted once
    R9  SAML phase error short-circuits before project phase
    R10 legacy arize_space_role='member' → Space Member role binding (ensure_legacy_equivalent_role)
    R11 project_admin still resolves via resolve_custom_space_role (custom path unchanged)

  CSV I/O:
    C1  write_results_csv with_projects=True includes project + project_emails columns
    C2  write_results_csv with_projects=False omits project columns (unchanged)

  CLI:
    L1  --project-assign flag is parsed, defaults to False
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
import responses as responses_lib

from arize_saml_bulk_setup.cli import build_parser
from arize_saml_bulk_setup.config import ARIZE_REST_API_URL
from arize_saml_bulk_setup.csv_io import write_results_csv
from arize_saml_bulk_setup.models import RowResult
from arize_saml_bulk_setup.projects import ProjectService
from arize_saml_bulk_setup.runner import BulkSetupRunner
from tests.conftest import RestResponses, StubExecutor


# ── module-level fixtures ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def mock_arize_sdk(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Prevent ProjectService from hitting the real ArizeClient SDK.

    Returns the mock instance so tests can assert on restrict() calls.
    """
    instance = MagicMock(name="ArizeClient_instance")
    monkeypatch.setattr(
        "arize_saml_bulk_setup.projects.ArizeClient",
        lambda **kwargs: instance,
    )
    return instance


# ── helpers ───────────────────────────────────────────────────────────────────


def _empty_idp() -> dict:
    return {
        "account": {
            "samlIdPs": {
                "edges": [
                    {
                        "node": {
                            "id": "Idp1",
                            "emailDomainsList": [{"domain": "acme.com"}],
                            "enforceSaml": False,
                            "syncUserRoles": False,
                            "signAuthn": False,
                            "allowLoginWithDefaults": False,
                            "roleMappings": [],
                        }
                    }
                ]
            }
        }
    }


def _build_project_svc(
    _rest_rsps: RestResponses,
    *,
    dry_run: bool = False,
) -> ProjectService:
    """Build a ProjectService with REST mocked."""
    return ProjectService(
        api_key="fake",
        logger=logging.getLogger("test"),
        dry_run=dry_run,
    )


def _build_runner_with_projects(
    mock_arize_client,
    *,
    dry_run: bool = False,
) -> BulkSetupRunner:
    runner = BulkSetupRunner(
        api_key="fake",
        dry_run=dry_run,
        verbose=False,
        project_assign=True,
    )
    runner.saml._execute_graphql = StubExecutor()
    return runner


def _stage_saml(runner: BulkSetupRunner, payload: dict) -> None:
    runner.saml._execute_graphql.responses.update(payload)


def _project_row(
    *,
    project: str = "Fraud Detector",
    project_emails: str = "alice@acme.com",
    space_role: str = "project_admin",
) -> dict:
    return {
        "organization": "Acme Corp",
        "space": "ML Platform",
        "arize_org_role": "member",
        "arize_space_role": space_role,
        "saml_attribute_name": "groups",
        "saml_attribute_value": "arize-ml",
        "project": project,
        "project_emails": project_emails,
    }


# ── P1: resolve_project — create new ─────────────────────────────────────────


def test_resolve_project_creates_when_missing(rest_responses: RestResponses) -> None:
    """P1: project not in list → POST /v2/projects → (id, 'created')."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj_1", "name": "Fraud Detector"})

    project_id, status = svc.resolve_project("Space_1", "ML Platform", "Fraud Detector")

    assert project_id == "Proj_1"
    assert status == "created"


# ── P2: resolve_project — already exists ─────────────────────────────────────


def test_resolve_project_returns_existing(rest_responses: RestResponses) -> None:
    """P2: project in GET /v2/projects list → (id, 'already_exists'), no POST."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_list(
        "/v2/projects",
        "projects",
        [{"id": "Proj_existing", "name": "Fraud Detector"}],
    )

    project_id, status = svc.resolve_project("Space_1", "ML Platform", "Fraud Detector")

    assert project_id == "Proj_existing"
    assert status == "already_exists"
    # No POST
    posted = [c for c in rest_responses.calls if c.request.method == "POST"]
    assert posted == []


# ── P3: restrict_project — success ───────────────────────────────────────────


def test_restrict_project_uses_arize_sdk(
    rest_responses: RestResponses, mock_arize_sdk: MagicMock
) -> None:
    """P3: restrict_project calls ArizeClient.resource_restrictions.restrict with project_id."""
    svc = _build_project_svc(rest_responses)

    status = svc.restrict_project("Proj123", "Acme/ML/FD")

    assert status == "restricted"
    mock_arize_sdk.resource_restrictions.restrict.assert_called_once_with(
        resource_id="Proj123"
    )


# ── P4: restrict_project — already restricted ────────────────────────────────


def test_restrict_project_idempotent_on_second_call(
    rest_responses: RestResponses,
) -> None:
    """P4: second call for same project_id → cache hit, 'already_restricted' without SDK call."""
    svc = _build_project_svc(rest_responses)

    status1 = svc.restrict_project("123", "label")
    assert status1 == "restricted"

    status2 = svc.restrict_project("123", "label")
    assert status2 == "already_restricted"


# ── P5: restrict_project — dry-run ───────────────────────────────────────────


def test_restrict_project_dry_run_skips_call(rest_responses: RestResponses) -> None:
    """P5: dry_run=True → no REST call, returns 'dry_run'."""
    svc = _build_project_svc(rest_responses, dry_run=True)

    status = svc.restrict_project("123", "label")

    assert status == "dry_run"
    posted = [c for c in rest_responses.calls if c.request.method == "POST"]
    assert posted == []


# ── P6: resolve_user — existing ──────────────────────────────────────────────


def test_resolve_user_returns_existing(rest_responses: RestResponses) -> None:
    """P6: user in GET /v2/users → (user_id, 'already_exists'), no POST."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_list(
        "/v2/users",
        "users",
        [{"id": "U1", "email": "alice@acme.com"}],
    )

    user_id, status = svc.resolve_user("alice@acme.com", "member")

    assert user_id == "U1"
    assert status == "already_exists"
    posted = [c for c in rest_responses.calls if c.request.method == "POST"]
    assert posted == []


# ── P7: resolve_user — auto-create ───────────────────────────────────────────


def test_resolve_user_creates_with_correct_org_role(rest_responses: RestResponses) -> None:
    """P7: user not found → POST /v2/users with org_role from CSV row, invite_mode=none."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_list("/v2/users", "users", [])
    create_mock = rest_responses.stub_post("/v2/users", {"id": "U_new"})

    user_id, status = svc.resolve_user("bob@acme.com", "viewer")

    assert user_id == "U_new"
    assert status == "created"
    assert create_mock.call_count == 1
    body = create_mock.calls[0].request.body
    import json
    payload = json.loads(body)
    assert payload["email"] == "bob@acme.com"
    # viewer has no predefined user role; falls back to "member"
    assert payload["role"] == {"type": "predefined", "name": "member"}
    assert payload["invite_mode"] == "none"


# ── P8: resolve_user — 409 race recovery ────────────────────────────────────


@responses_lib.activate
def test_resolve_user_recovers_on_409_race() -> None:
    """P8: POST /v2/users returns 409 → reload users list and return existing ID."""
    svc = ProjectService(
        api_key="fake",
        logger=logging.getLogger("test"),
        dry_run=False,
    )

    # First GET: empty (before the race); POST: 409; second GET: has the user
    responses_lib.add(
        responses_lib.GET,
        f"{ARIZE_REST_API_URL}/v2/users",
        json={"users": [], "pagination": {"has_more": False}},
        status=200,
    )
    responses_lib.add(
        responses_lib.POST,
        f"{ARIZE_REST_API_URL}/v2/users",
        status=409,
        json={"error": "conflict"},
    )
    responses_lib.add(
        responses_lib.GET,
        f"{ARIZE_REST_API_URL}/v2/users",
        json={
            "users": [{"id": "U_race", "email": "carol@acme.com"}],
            "pagination": {"has_more": False},
        },
        status=200,
    )

    user_id, status = svc.resolve_user("carol@acme.com", "member")
    assert user_id == "U_race"
    assert status == "already_exists"


# ── P9: assign_user_to_project — granted ─────────────────────────────────────


def test_assign_user_to_project_granted(rest_responses: RestResponses) -> None:
    """P9: POST /v2/role-bindings 201 → 'granted'."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)

    status = svc.assign_user_to_project("U1", "Proj1", "Role1")
    assert status == "granted"


# ── P10: assign_user_to_project — already_granted ───────────────────────────


def test_assign_user_to_project_idempotent_on_409(rest_responses: RestResponses) -> None:
    """P10: 409 from role_bindings → 'already_granted', not an error."""
    svc = _build_project_svc(rest_responses)
    rest_responses.stub_post("/v2/role-bindings", {"error": "duplicate"}, status=409)

    status = svc.assign_user_to_project("U1", "Proj1", "Role1")
    assert status == "already_granted"


# ── P11: assign_user_to_project — dry-run ────────────────────────────────────


def test_assign_user_to_project_dry_run(rest_responses: RestResponses) -> None:
    """P11: dry_run=True → loads existing bindings, no POST, returns 'dry_run' for new binding."""
    svc = _build_project_svc(rest_responses, dry_run=True)
    # No existing bindings for this user+project pair
    rest_responses.stub_list("/v2/role-bindings", "role_bindings", [])

    status = svc.assign_user_to_project("U1", "Proj1", "Role1")

    assert status == "dry_run"
    posted = [c for c in rest_responses.calls if c.request.method == "POST"]
    assert posted == []


# ── R1: project_assign=False → columns ignored ──────────────────────────────


def test_project_assign_false_ignores_project_columns(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """R1: project_assign=False → project phase never runs even if columns exist."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    runner = BulkSetupRunner(api_key="fake", dry_run=True, verbose=False, project_assign=False)
    runner.saml._execute_graphql = StubExecutor()
    runner.saml._execute_graphql.responses["getSAMLIdP"] = _empty_idp()

    rows = [{**sample_row, "project": "Fraud Detector", "project_emails": "alice@acme.com"}]
    results = runner.run(rows)

    assert results[0].status == "dry_run"
    # No /v2/projects or /v2/role-bindings calls should fire
    paths = [c.request.path_url for c in rest_responses.calls]
    assert not any("/v2/projects" in p for p in paths)
    assert not any("/v2/role-bindings" in p for p in paths)


# ── R2: project_assign=True, row has no project → no project phase ───────────


def test_project_assign_skips_row_with_no_project(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """R2: --project-assign is on, but row has no 'project' → only SAML phase."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    runner = _build_runner_with_projects(mock_arize_client, dry_run=True)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [{**sample_row, "project": "", "project_emails": ""}]
    results = runner.run(rows)

    assert results[0].status == "dry_run"
    paths = [c.request.path_url for c in rest_responses.calls]
    assert not any("/v2/projects" in p for p in paths)


# ── R3: unknown role → row error ─────────────────────────────────────────────


def test_project_assign_unknown_role_errors_row(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R3: arize_space_role is not a legacy alias and not in GET /v2/roles → row error."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    # Roles cache does not contain "nonexistent_role"
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row(space_role="nonexistent_role")]
    results = runner.run(rows)

    assert results[0].status == "error"
    assert "nonexistent_role" in results[0].error_message


# ── R4: missing project_emails → row error ───────────────────────────────────


def test_project_assign_missing_emails_errors_row(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R4: project column is set but project_emails is empty → row error."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    # project_admin is treated as a custom RBAC role during the SAML phase.
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row(project_emails="")]
    results = runner.run(rows)

    assert results[0].status == "error"
    assert "project_emails" in results[0].error_message


# ── R5: happy path ───────────────────────────────────────────────────────────


def test_project_assign_happy_path(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R5: full project-assign flow — project created, restricted, users assigned."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    # Roles cache: project_admin role
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    # Projects: empty → will create
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj1", "name": "Fraud Detector"})
    # Users: alice exists, bob doesn't
    rest_responses.stub_list(
        "/v2/users",
        "users",
        [{"id": "U_alice", "email": "alice@acme.com"}],
    )
    rest_responses.stub_post("/v2/users", {"id": "U_bob"})
    # Role bindings
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB2"}, status=201)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row(project_emails="alice@acme.com,bob@acme.com")]
    results = runner.run(rows)

    assert results[0].status != "error", results[0].error_message
    assert "Fraud Detector" in results[0].note
    assert runner.projects_created == 1
    assert runner.users_created_for_project == 1
    assert runner.project_assignments_created == 2


# ── R6: dry-run project phase ────────────────────────────────────────────────


def test_project_assign_dry_run_no_api_writes(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R6: dry_run=True → project phase logs actions but fires no POST."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", []
    )
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    rest_responses.stub_list("/v2/users", "users", [])
    rest_responses.stub_list("/v2/role-bindings", "role_bindings", [])

    runner = _build_runner_with_projects(mock_arize_client, dry_run=True)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row()]
    results = runner.run(rows)

    assert results[0].status == "dry_run"
    posted = [c for c in rest_responses.calls if c.request.method == "POST"]
    assert posted == [], f"Unexpected POSTs: {[c.request.url for c in posted]}"


# ── R7: idempotent run ───────────────────────────────────────────────────────


def test_project_assign_idempotent_notes(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R7: project + user already exist → already_exists / already_granted in note."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    rest_responses.stub_list(
        "/v2/projects", "projects", [{"id": "Proj1", "name": "Fraud Detector"}]
    )
    rest_responses.stub_list(
        "/v2/users", "users", [{"id": "U1", "email": "alice@acme.com"}]
    )
    rest_responses.stub_post("/v2/role-bindings", {"error": "duplicate"}, status=409)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row()]
    results = runner.run(rows)

    assert results[0].status != "error", results[0].error_message
    assert runner.projects_existed == 1
    assert runner.project_assignments_existed == 1
    assert runner.project_assignments_created == 0


# ── R8: project counter deduplication ────────────────────────────────────────


def test_project_counter_deduplicates_across_rows(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R8: two rows referencing the same project count it once, not twice."""
    for _ in range(2):
        rest_responses.stub_list(
            "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
        )
        rest_responses.stub_list(
            "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
        )
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    # First request: project missing → create; subsequent: already cached
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj1", "name": "Fraud Detector"})
    rest_responses.stub_list(
        "/v2/users",
        "users",
        [
            {"id": "U1", "email": "alice@acme.com"},
            {"id": "U2", "email": "bob@acme.com"},
        ],
    )
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB2"}, status=201)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [
        _project_row(project_emails="alice@acme.com"),
        {**_project_row(project_emails="bob@acme.com"), "saml_attribute_value": "arize-fraud"},
    ]
    runner.run(rows)

    assert runner.projects_created == 1
    assert runner.projects_existed == 0  # deduplicated


# ── R9: SAML error short-circuits project phase ──────────────────────────────


def test_saml_error_short_circuits_before_project_phase(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R9: if SAML pre-flight fails, project phase never runs."""
    runner = _build_runner_with_projects(mock_arize_client, dry_run=True)
    # No SAML IdP → pre-flight error for all rows
    runner.saml._execute_graphql.responses["getSAMLIdP"] = {
        "account": {"samlIdPs": {"edges": []}}
    }

    rows = [_project_row()]
    results = runner.run(rows)

    assert all(r.status == "error" for r in results)
    assert all("No SAML IdP found" in r.error_message for r in results)
    # Project fields preserved on error rows
    assert results[0].project == "Fraud Detector"
    assert results[0].project_emails == "alice@acme.com"
    # No project API calls
    paths = [c.request.path_url for c in rest_responses.calls]
    assert not any("/v2/projects" in p for p in paths)


# ── R10: legacy member role → Space Member role binding ──────────────────────


def test_project_assign_legacy_member_uses_space_member_role(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R10: arize_space_role='member' → ensure_legacy_equivalent_role('member')
    resolves to Space Member relay ID for the project binding."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Subsidiary Inc"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "NLP Research"}]
    )
    # Space Member already exists on this account
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RoleSM", "name": "Space Member"}]
    )
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj1", "name": "Chatbot QA"})
    rest_responses.stub_list(
        "/v2/users", "users", [{"id": "U1", "email": "lead@subsidiary.com"}]
    )
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [{
        "organization": "Subsidiary Inc",
        "space": "NLP Research",
        "arize_org_role": "member",
        "arize_space_role": "member",
        "saml_attribute_name": "roles",
        "saml_attribute_value": "arize-nlp-engineers",
        "project": "Chatbot QA",
        "project_emails": "lead@subsidiary.com",
    }]
    results = runner.run(rows)

    assert results[0].status != "error", results[0].error_message
    assert runner.project_assignments_created == 1
    # Binding should have used the Space Member relay ID
    rb_calls = [c for c in rest_responses.calls if "/v2/role-bindings" in c.request.path_url]
    import json
    assert json.loads(rb_calls[0].request.body)["role_id"] == "RoleSM"


# ── R11: project_admin still resolves via custom path ────────────────────────


def test_project_assign_project_admin_uses_custom_role_path(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R11: arize_space_role='project_admin' → resolve_custom_space_role (unchanged)."""
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePA", "name": "project_admin"}]
    )
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj1", "name": "Fraud Detector"})
    rest_responses.stub_list(
        "/v2/users", "users", [{"id": "U1", "email": "alice@acme.com"}]
    )
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [_project_row(space_role="project_admin")]
    results = runner.run(rows)

    assert results[0].status != "error", results[0].error_message
    import json
    rb_calls = [c for c in rest_responses.calls if "/v2/role-bindings" in c.request.path_url]
    assert json.loads(rb_calls[0].request.body)["role_id"] == "RolePA"


# ── R_project_only: SAML columns empty → skip SAML phase ────────────────────


def test_project_only_row_skips_saml_phase(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """R_project_only: row with empty SAML columns runs only the project phase.

    No SAML mapping is queued; org/space are still resolved; project is
    created, restricted, and the user is assigned.
    """
    rest_responses.stub_list(
        "/v2/organizations", "organizations", [{"id": "Org1", "name": "Acme Corp"}]
    )
    rest_responses.stub_list(
        "/v2/spaces", "spaces", [{"id": "Space1", "name": "ML Platform"}]
    )
    rest_responses.stub_list(
        "/v2/roles", "roles", [{"id": "RolePV", "name": "project_viewer"}]
    )
    rest_responses.stub_list("/v2/projects", "projects", [])
    rest_responses.stub_post("/v2/projects", {"id": "Proj1", "name": "Insurance Risk"})
    rest_responses.stub_list(
        "/v2/users", "users", [{"id": "U1", "email": "carol@acme.com"}]
    )
    rest_responses.stub_post("/v2/role-bindings", {"id": "RB1"}, status=201)

    runner = _build_runner_with_projects(mock_arize_client, dry_run=False)
    _stage_saml(runner, {"getSAMLIdP": _empty_idp()})

    rows = [{
        "organization": "Acme Corp",
        "space": "ML Platform",
        "arize_org_role": "",
        "arize_space_role": "project_viewer",
        "saml_attribute_name": "",
        "saml_attribute_value": "",
        "project": "Insurance Risk",
        "project_emails": "carol@acme.com",
    }]
    results = runner.run(rows)

    assert results[0].status != "error", results[0].error_message
    assert runner.project_assignments_created == 1
    # No SAML mappings queued
    assert runner.mappings_created == 0


# ── C1: write_results_csv with_projects=True ─────────────────────────────────


def test_write_results_csv_with_projects_includes_columns(tmp_path) -> None:
    """C1: with_projects=True → output CSV has 'project' and 'project_emails' columns."""
    results = [
        RowResult(
            row_number=1,
            organization="Acme",
            space="ML",
            arize_org_role="member",
            arize_space_role="project_admin",
            saml_attribute_name="groups",
            saml_attribute_value="arize-ml",
            project="Fraud Detector",
            project_emails="alice@acme.com",
            status="created",
        )
    ]
    out = tmp_path / "results.csv"
    write_results_csv(results, str(out), with_projects=True)

    text = out.read_text()
    header = text.split("\n")[0]
    assert "project" in header
    assert "project_emails" in header
    assert "Fraud Detector" in text
    assert "alice@acme.com" in text


# ── C2: write_results_csv with_projects=False omits columns ──────────────────


def test_write_results_csv_without_projects_omits_columns(tmp_path) -> None:
    """C2: with_projects=False (default) → no project/project_emails columns."""
    results = [
        RowResult(
            row_number=1,
            organization="Acme",
            space="ML",
            arize_org_role="member",
            arize_space_role="admin",
            saml_attribute_name="groups",
            saml_attribute_value="arize-ml",
            status="created",
        )
    ]
    out = tmp_path / "results.csv"
    write_results_csv(results, str(out), with_projects=False)

    header = out.read_text().split("\n")[0]
    assert "project" not in header


# ── L1: CLI --project-assign flag ────────────────────────────────────────────


def test_cli_project_assign_flag_defaults_false() -> None:
    """L1: --project-assign defaults to False; passes True when supplied."""
    parser = build_parser()
    ns = parser.parse_args(["--csv", "x.csv"])
    assert ns.project_assign is False

    ns = parser.parse_args(["--csv", "x.csv", "--project-assign"])
    assert ns.project_assign is True
