"""BulkSetupRunner end-to-end paths — covers TEST_SCENARIOS.md section 8.

  8.1, 8.2 — dry-run end-to-end (all rows dry_run; mixed cached/new counters)
  8.3      — --verbose toggles DEBUG level
  8.4, 8.5 — flush failure flips queued 'created' → 'error', preserves prior errors
  8.6, 8.7 — SAML pre-flight fail-fast (missing IdP, transport error)
  8.8      — repeated POST /v2/organizations failure short-circuits via failure cache
  8.9      — per-row traceback is suppressed at INFO, shown at DEBUG (--verbose)
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
import responses

from arize_saml_bulk_setup.runner import BulkSetupRunner
from tests.conftest import RestResponses, StubExecutor


def _empty_idp_with_no_mappings() -> dict:
    """A getSAMLIdP response with one existing IdP that has no role mappings."""
    return {
        "account": {
            "samlIdPs": {
                "edges": [
                    {
                        "node": {
                            "id": "Idp_existing",
                            "emailDomainsList": [{"domain": "acme.com"}],
                            "enforceSaml": False,
                            "syncUserRoles": True,
                            "signAuthn": False,
                            "allowLoginWithDefaults": False,
                            "roleMappings": [],
                        }
                    }
                ]
            }
        }
    }


def _build_runner(
    mock_arize_client,
    *,
    dry_run: bool = True,
    verbose: bool = False,
    extra_kwargs: dict[str, Any] | None = None,
) -> BulkSetupRunner:
    """Construct a runner whose SAML executor is a StubExecutor we control.

    The ArizeClient is already mocked by `mock_arize_client` (it's still
    instantiated as the GraphQL transport for SAML, but its REST methods are
    never used now). We then swap the SAML service's executor so we can stage
    GraphQL responses per test.
    """
    runner = BulkSetupRunner(
        api_key="fake",
        dry_run=dry_run,
        verbose=verbose,
        **(extra_kwargs or {}),
    )
    runner.saml._execute_graphql = StubExecutor()
    return runner


def _stage(runner: BulkSetupRunner, payload: dict[str, Any]) -> None:
    runner.saml._execute_graphql.responses.update(payload)


# ── 8.1, 8.2: Dry-run end-to-end ─────────────────────────────────────────────


def test_dry_run_marks_all_rows_dry_run_and_writes_nothing(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """8.1: dry_run=True → all rows status='dry_run'; no createSAMLIdP / updateSAMLIdP /
    POST /v2/organizations / POST /v2/spaces calls."""
    runner = _build_runner(mock_arize_client, dry_run=True)
    _stage(runner, {"getSAMLIdP": _empty_idp_with_no_mappings()})
    # Empty org list — both names will go through the dry-run create branch.
    rest_responses.stub_list("/v2/organizations", "organizations", [])

    rows = [
        sample_row,
        {**sample_row, "saml_attribute_value": "arize-fraud"},  # different mapping
    ]
    results = runner.run(rows)

    assert all(r.status == "dry_run" for r in results), [
        (r.row_number, r.status, r.error_message) for r in results
    ]
    assert runner.mappings_created == 2
    # No write-side GraphQL ops should have been issued
    ops = [op for op, _ in runner.saml._execute_graphql.calls]
    assert "createSAMLIdP" not in ops
    assert "updateSAMLIdP" not in ops
    # No POST /v2/organizations or /v2/spaces should have fired (dry-run).
    posted_paths = [
        c.request.path_url for c in rest_responses.calls if c.request.method == "POST"
    ]
    assert posted_paths == []


def test_dry_run_counters_split_created_vs_existed(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """8.2: with one cached org from GET /v2/organizations, counters report both."""
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_existing", "name": "ML Platform"}],
    )
    runner = _build_runner(mock_arize_client, dry_run=True)
    _stage(runner, {"getSAMLIdP": _empty_idp_with_no_mappings()})

    rows = [
        sample_row,  # Acme Corp / ML Platform — both cached
        {
            **sample_row,
            "organization": "New Org",
            "space": "New Space",
            "saml_attribute_value": "arize-new",
        },  # both new
    ]
    runner.run(rows)

    assert runner.orgs_existed == 1
    assert runner.orgs_created == 1
    assert runner.spaces_existed == 1
    assert runner.spaces_created == 1


# ── 8.3: --verbose toggles DEBUG ─────────────────────────────────────────────


def test_dry_run_warns_when_custom_role_missing(
    mock_arize_client,
    rest_responses: RestResponses,
    sample_row,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Dry-run: a CSV row referencing a nonexistent custom RBAC role surfaces a
    WARNING + note, doesn't error, and doesn't queue a SAML mapping."""
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_ml", "name": "ML Platform"}],
    )
    # Account has one custom role, but the CSV asks for a different one.
    rest_responses.stub_list(
        "/v2/roles",
        "roles",
        [{"id": "Um9sZTox", "name": "Project Reviewer"}],
    )
    runner = _build_runner(mock_arize_client, dry_run=True)
    _stage(runner, {"getSAMLIdP": _empty_idp_with_no_mappings()})

    rows = [
        {**sample_row, "arize_space_role": "Nonexistent Role"},
    ]
    results = runner.run(rows)

    # Not an error — a dry-run with a note.
    assert results[0].status == "dry_run"
    assert results[0].error_message == ""
    assert "Nonexistent Role" in results[0].note
    assert "does not exist" in results[0].note
    # Warning surfaced in stdout (the runner's logger has propagate=False).
    out = capsys.readouterr().out
    assert "Row 1:" in out and "Nonexistent Role" in out
    # No mapping was queued — pending stays empty, no createSAMLIdP/updateSAMLIdP.
    assert runner.mappings_created == 0
    ops = [op for op, _ in runner.saml._execute_graphql.calls]
    assert "createSAMLIdP" not in ops
    assert "updateSAMLIdP" not in ops


def test_wet_run_errors_when_custom_role_missing(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """Wet run (dry_run=False) keeps the original error behavior — missing role → row errors."""
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_ml", "name": "ML Platform"}],
    )
    rest_responses.stub_list(
        "/v2/roles",
        "roles",
        [{"id": "Um9sZTox", "name": "Project Reviewer"}],
    )
    runner = _build_runner(mock_arize_client, dry_run=False)
    _stage(runner, {"getSAMLIdP": _empty_idp_with_no_mappings()})

    results = runner.run(
        [{**sample_row, "arize_space_role": "Nonexistent Role"}]
    )

    assert results[0].status == "error"
    assert "not found in this account" in results[0].error_message


def test_verbose_sets_logger_to_debug() -> None:
    """8.3: --verbose flips the logger from INFO to DEBUG.

    Tested via the static _build_logger helper because all runner instances
    share the same `arize_bulk_setup` logger (last setLevel wins), so checking
    the level on two coexisting runners doesn't reflect reality.
    """
    quiet = BulkSetupRunner._build_logger(verbose=False)
    assert quiet.level == logging.INFO
    verbose = BulkSetupRunner._build_logger(verbose=True)
    assert verbose.level == logging.DEBUG


# ── 8.4, 8.5: Flush failure rollback ─────────────────────────────────────────


def test_flush_failure_flips_created_rows_to_error(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """8.4: updateSAMLIdP error response → all queued 'created' rows flip to 'error'."""
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_ml", "name": "ML Platform"}],
    )
    runner = _build_runner(mock_arize_client, dry_run=False)
    _stage(
        runner,
        {
            "getSAMLIdP": _empty_idp_with_no_mappings(),
            "updateSAMLIdP": {
                "updateSAMLIdP": {"idp": None, "error": "domain locked"}
            },
        },
    )

    rows = [
        sample_row,
        {**sample_row, "saml_attribute_value": "arize-other"},
    ]
    results = runner.run(rows)

    assert all(r.status == "error" for r in results)
    assert all("SAML update failed" in r.error_message for r in results)
    assert all("domain locked" in r.error_message for r in results)


def test_flush_failure_does_not_flip_pre_existing_errors(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """8.5: a row that errored before the flush keeps its original error message."""
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_ml", "name": "ML Platform"}],
    )
    runner = _build_runner(mock_arize_client, dry_run=False)
    _stage(
        runner,
        {
            "getSAMLIdP": _empty_idp_with_no_mappings(),
            "updateSAMLIdP": {"updateSAMLIdP": {"idp": None, "error": "boom"}},
        },
    )

    rows = [
        # Row 1: invalid → error before the flush
        {**sample_row, "arize_org_role": "owner"},
        # Row 2: valid → queued → flipped by flush failure
        sample_row,
    ]
    results = runner.run(rows)

    assert results[0].status == "error"
    assert "Invalid arize_org_role" in results[0].error_message  # untouched
    assert results[1].status == "error"
    assert "SAML update failed" in results[1].error_message


# ── 8.6, 8.7: SAML pre-flight fail-fast ──────────────────────────────────────


def test_missing_saml_idp_short_circuits_with_single_error(
    mock_arize_client,
    rest_responses: RestResponses,
    sample_row,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """8.6: no IdP + no creation params → log ONCE, every row gets the same
    message, no per-row getSAMLIdP retries, no traceback noise.

    The runner's logger has propagate=False, so we read captured stdout
    rather than using caplog.
    """
    runner = _build_runner(mock_arize_client, dry_run=True)
    # Empty edges = no IdP on the account; no metadata args were provided.
    _stage(runner, {"getSAMLIdP": {"account": {"samlIdPs": {"edges": []}}}})

    rows = [
        sample_row,
        {**sample_row, "saml_attribute_value": "arize-fraud"},
        {**sample_row, "saml_attribute_value": "arize-nlp"},
    ]
    results = runner.run(rows)

    # Every row carries the same actionable error message
    assert all(r.status == "error" for r in results)
    assert all("No SAML IdP found" in r.error_message for r in results)
    assert all("--saml-metadata-url" in r.error_message for r in results)

    # Pre-flight made exactly ONE getSAMLIdP call — not one per row
    get_calls = [c for c in runner.saml._execute_graphql.calls if c[0] == "getSAMLIdP"]
    assert len(get_calls) == 1

    # The "No SAML IdP found" line was emitted exactly once — not per row
    out = capsys.readouterr().out
    assert out.count("No SAML IdP found") == 1, (
        f"expected 1 log line, got {out.count('No SAML IdP found')}"
    )


def test_saml_load_transport_error_short_circuits(
    mock_arize_client, sample_row
) -> None:
    """8.7: a non-RuntimeError exception during ensure_loaded (e.g. transport
    error) is reported with a distinct message that says "Could not load SAML"
    rather than the "IdP doesn't exist" message."""
    runner = _build_runner(mock_arize_client, dry_run=True)

    # Configure the stub executor to raise on getSAMLIdP (simulating a network /
    # transport / schema error — anything that isn't our own RuntimeError).
    class BoomExecutor:
        calls: list[tuple[str, dict]] = []

        def __call__(self, query, variables, op_name):
            self.calls.append((op_name, variables))
            raise ConnectionError("DNS failure")

    runner.saml._execute_graphql = BoomExecutor()

    results = runner.run([sample_row])

    assert all(r.status == "error" for r in results)
    # Different message from the "IdP doesn't exist" case
    assert all("Could not load SAML" in r.error_message for r in results)
    assert all("DNS failure" in r.error_message for r in results)


# ── 8.8: repeated POST /v2/organizations failure is deduplicated ─────────────


def test_repeated_org_create_failure_short_circuits(
    mock_arize_client, rest_responses: RestResponses, sample_row
) -> None:
    """8.8: when POST /v2/organizations fails on row 1, rows 2..N referencing the
    same org skip the API call and surface a clearer 'earlier attempt failed'
    message instead of re-firing the same broken call N times."""
    runner = _build_runner(mock_arize_client, dry_run=False)
    _stage(runner, {"getSAMLIdP": _empty_idp_with_no_mappings()})

    # Empty list, then a single failing POST. Subsequent POSTs would 500 if
    # they fired — but the failure cache should mean they don't fire at all.
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    create_org = rest_responses.stub_post(
        "/v2/organizations",
        response_body={"error": "INTERNAL_SERVER_ERROR"},
        status=500,
    )

    rows = [
        sample_row,
        {**sample_row, "saml_attribute_value": "g2"},
        {**sample_row, "saml_attribute_value": "g3"},
        {**sample_row, "saml_attribute_value": "g4"},
    ]
    results = runner.run(rows)

    # Every row errors
    assert all(r.status == "error" for r in results)
    # Row 1 carries the upstream 500 error
    assert "500" in results[0].error_message
    # Rows 2..N carry the dedup message
    for r in results[1:]:
        assert "Earlier attempt to create organization" in r.error_message, (
            r.error_message
        )
        assert "Acme Corp" in r.error_message

    # The POST fired exactly ONCE — not per row
    assert create_org.call_count == 1


# ── 8.10: reconcile against existing IdP (the user's reported scenario) ─────


def _idp_with_existing_custom_mappings() -> dict:
    """IdP with two existing custom-role mappings on NLP Research — mirrors
    the user's run that triggered the duplicate-mapping bug.

    - attrs=[["roles","arize-nlp-engineers"]] → spaceRbacRolesMap=[["S_nlp", Space Member]]
    - attrs=[["roles","arize-nlp-leads"]]     → spaceRbacRolesMap=[["S_nlp", Testing Custom Role]]
    """
    return {
        "account": {
            "samlIdPs": {
                "edges": [
                    {
                        "node": {
                            "id": "Idp_existing",
                            "emailDomainsList": [{"domain": "acme.com"}],
                            "enforceSaml": False,
                            "syncUserRoles": True,
                            "signAuthn": False,
                            "allowLoginWithDefaults": False,
                            "roleMappings": [
                                {
                                    "id": "RM_engineers",
                                    "attributesMap": [["roles", "arize-nlp-engineers"]],
                                    "spaceRolesMap": [],
                                    "spaceRbacRolesMap": [
                                        ["S_nlp", "Um9sZTpNRU1CRVI="]
                                    ],
                                    "isAccountAdmin": False,
                                    "orgRole": {"orgId": "Org_sub", "roleId": "member"},
                                },
                                {
                                    "id": "RM_leads",
                                    "attributesMap": [["roles", "arize-nlp-leads"]],
                                    "spaceRolesMap": [],
                                    "spaceRbacRolesMap": [
                                        ["S_nlp", "Um9sZTpURVNUSU5H"]
                                    ],
                                    "isAccountAdmin": False,
                                    "orgRole": {"orgId": "Org_sub", "roleId": "member"},
                                },
                            ],
                        }
                    }
                ]
            }
        }
    }


def test_reconcile_idempotent_and_replace_against_existing_idp(
    mock_arize_client, rest_responses: RestResponses
) -> None:
    """8.10 (the bug the user hit): existing IdP has custom-role mappings for
    arize-nlp-engineers (Space Member) and arize-nlp-leads (Testing Custom Role)
    on NLP Research. CSV row 1 asks for member (idempotent), CSV row 2 asks for
    admin (replace). After run:

      - Row 1: status='already_exists' with the idempotent note
      - Row 2: status='created' with the 'replaced prior role' note
      - updateSAMLIdP payload has exactly TWO mappings (no duplicates)
      - The leads mapping's role is now Space Admin for NLP Research
    """
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_sub", "name": "Subsidiary Inc"}],
    )
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "S_nlp", "name": "NLP Research"}],
    )
    # Custom roles cache for legacy-equivalent lookup.
    rest_responses.stub_list(
        "/v2/roles",
        "roles",
        [
            {"id": "Um9sZTpNRU1CRVI=", "name": "Space Member"},
            {"id": "Um9sZTpBRE1JTg==", "name": "Space Admin"},
        ],
    )
    runner = _build_runner(mock_arize_client, dry_run=False)
    _stage(
        runner,
        {
            "getSAMLIdP": _idp_with_existing_custom_mappings(),
            "updateSAMLIdP": {
                "updateSAMLIdP": {
                    "idp": {"id": "Idp_existing", "roleMappings": []},
                    "error": None,
                }
            },
        },
    )

    rows = [
        {
            "organization": "Subsidiary Inc",
            "space": "NLP Research",
            "arize_org_role": "member",
            "arize_space_role": "member",  # legacy → Space Member custom (idempotent)
            "saml_attribute_name": "roles",
            "saml_attribute_value": "arize-nlp-engineers",
        },
        {
            "organization": "Subsidiary Inc",
            "space": "NLP Research",
            "arize_org_role": "member",
            "arize_space_role": "admin",  # legacy → Space Admin custom (replace)
            "saml_attribute_name": "roles",
            "saml_attribute_value": "arize-nlp-leads",
        },
    ]
    results = runner.run(rows)

    # Row statuses + notes
    assert results[0].status == "already_exists"
    assert "already covers this space" in results[0].note
    assert results[1].status == "created"
    assert "Replaced prior role" in results[1].note
    assert "Um9sZTpURVNUSU5H" in results[1].note  # the old role

    # updateSAMLIdP fired exactly once with EXACTLY two mappings (no duplicates)
    update_calls = [c for c in runner.saml._execute_graphql.calls if c[0] == "updateSAMLIdP"]
    assert len(update_calls) == 1
    payload = update_calls[0][1]["input"]
    mappings = payload["roleMappings"]["mappingsList"]
    assert len(mappings) == 2

    # Engineers mapping kept its original role
    engineers = next(
        m for m in mappings
        if m["attributesMap"] == [["roles", "arize-nlp-engineers"]]
    )
    assert engineers["spaceRbacRolesMap"] == [["S_nlp", "Um9sZTpNRU1CRVI="]]

    # Leads mapping's role was REPLACED to Space Admin
    leads = next(
        m for m in mappings
        if m["attributesMap"] == [["roles", "arize-nlp-leads"]]
    )
    assert leads["spaceRbacRolesMap"] == [["S_nlp", "Um9sZTpBRE1JTg=="]]


# ── 8.9: traceback suppressed at INFO, shown at DEBUG ────────────────────────


def test_row_error_traceback_only_shown_with_verbose(
    mock_arize_client,
    rest_responses: RestResponses,
    sample_row,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """8.9: at INFO (default), per-row errors log a single line. At DEBUG
    (--verbose), the same error also includes the Python traceback."""
    rows = [sample_row]

    # Stage two list responses (for the two runner constructions) and two
    # failing POSTs. `responses` consumes registrations FIFO when the same
    # endpoint is registered multiple times.
    for _ in range(2):
        rest_responses.stub_list("/v2/organizations", "organizations", [])
        rest_responses.stub_post(
            "/v2/organizations",
            response_body={"error": "boom from upstream"},
            status=500,
        )

    # First: non-verbose run
    runner_quiet = _build_runner(mock_arize_client, verbose=False, dry_run=False)
    _stage(runner_quiet, {"getSAMLIdP": _empty_idp_with_no_mappings()})
    runner_quiet.run(rows)
    quiet_out = capsys.readouterr().out
    assert "Row 1 failed:" in quiet_out
    assert "500" in quiet_out
    assert "Traceback" not in quiet_out

    # Then: verbose run — same setup, but logger at DEBUG
    runner_verbose = _build_runner(mock_arize_client, verbose=True, dry_run=False)
    _stage(runner_verbose, {"getSAMLIdP": _empty_idp_with_no_mappings()})
    runner_verbose.run(rows)
    verbose_out = capsys.readouterr().out
    assert "Row 1 failed:" in verbose_out
    assert "500" in verbose_out
    assert "Traceback" in verbose_out
