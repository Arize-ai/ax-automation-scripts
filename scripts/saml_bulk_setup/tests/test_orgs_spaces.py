"""OrgSpaceService REST paths — org/space list, create, dry-run, failure caching.

Tests use the `rest_responses` fixture (responses.RequestsMock) to stage
canned REST responses against https://api.arize.com/v2/* and the
`mock_arize_client` fixture to keep toolkit construction inert.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlsplit

import pytest
import responses

from arize_saml_bulk_setup.orgs_spaces import OrgSpaceService

from tests.conftest import RestResponses


def _service(
    mock_arize_client, logger: logging.Logger, *, dry_run: bool = False
) -> OrgSpaceService:
    return OrgSpaceService(api_key="fake", logger=logger, dry_run=dry_run)


def _post_bodies(rsps: responses.RequestsMock, path: str) -> list[bytes]:
    return [c.request.body for c in rsps.calls if c.request.path_url == path]


def _query_params(rsps: responses.RequestsMock, path_prefix: str) -> list[dict]:
    """Parsed query strings of every GET request whose path begins with `path_prefix`."""
    out: list[dict] = []
    for c in rsps.calls:
        url = urlsplit(c.request.url)
        if url.path == path_prefix and c.request.method == "GET":
            out.append({k: v[0] for k, v in parse_qs(url.query).items()})
    return out


# ── Org list ─────────────────────────────────────────────────────────────────


def test_resolve_org_returns_cached_id_without_create(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list(
        "/v2/organizations",
        "organizations",
        [{"id": "Org_acme", "name": "Acme Corp"}],
    )
    svc = _service(mock_arize_client, logger)

    org_id, status = svc.resolve_org("Acme Corp")
    assert org_id == "Org_acme"
    assert status == "already_exists"
    # No POST should have fired
    assert all(c.request.method == "GET" for c in rest_responses.calls)


def test_resolve_org_follows_pagination(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    # Two pages, then halt
    rest_responses._rsps.add(
        responses.GET,
        "https://api.arize.com/v2/organizations",
        json={
            "organizations": [{"id": "Org_a", "name": "A"}],
            "pagination": {"has_more": True, "next_cursor": "c2"},
        },
        status=200,
    )
    rest_responses._rsps.add(
        responses.GET,
        "https://api.arize.com/v2/organizations",
        json={
            "organizations": [{"id": "Org_b", "name": "B"}],
            "pagination": {"has_more": False},
        },
        status=200,
    )
    svc = _service(mock_arize_client, logger)

    assert svc.resolve_org("A")[0] == "Org_a"
    assert svc.resolve_org("B")[0] == "Org_b"

    queries = _query_params(rest_responses._rsps, "/v2/organizations")
    assert queries[0].get("cursor") is None
    assert queries[1].get("cursor") == "c2"


# ── Org create ───────────────────────────────────────────────────────────────


def test_resolve_org_creates_when_missing(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    rest_responses.stub_post(
        "/v2/organizations",
        response_body={"id": "Org_new", "name": "New Co"},
        status=201,
    )
    svc = _service(mock_arize_client, logger)

    org_id, status = svc.resolve_org("New Co")
    assert org_id == "Org_new"
    assert status == "created"
    bodies = _post_bodies(rest_responses._rsps, "/v2/organizations")
    assert bodies == [b'{"name": "New Co"}']


def test_repeated_org_create_failure_is_cached(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    """A persistent 500 from POST /v2/organizations short-circuits subsequent calls."""
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    failing_post = rest_responses.stub_post(
        "/v2/organizations",
        response_body={"error": "internal"},
        status=500,
    )
    svc = _service(mock_arize_client, logger)

    with pytest.raises(Exception):
        svc.resolve_org("New Co")
    with pytest.raises(RuntimeError, match="Earlier attempt"):
        svc.resolve_org("New Co")

    # POST fired exactly once across both calls — second call short-circuits.
    assert failing_post.call_count == 1


def test_dry_run_org_creation_skips_post(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    svc = _service(mock_arize_client, logger, dry_run=True)

    org_id, status = svc.resolve_org("Brand New")
    assert status == "dry_run"
    assert org_id.startswith("__dry_run_org_")
    assert [c.request.method for c in rest_responses.calls] == ["GET"]


# ── Space list ───────────────────────────────────────────────────────────────


def test_resolve_space_returns_cached_id_and_scopes_to_org(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    rest_responses.stub_list(
        "/v2/spaces",
        "spaces",
        [{"id": "Space_ml", "name": "ML Platform"}],
    )
    svc = _service(mock_arize_client, logger)

    space_id, status = svc.resolve_space("Org_acme", "Acme Corp", "ML Platform")
    assert space_id == "Space_ml"
    assert status == "already_exists"

    # GET /v2/spaces must have been scoped by organization_id query param.
    queries = _query_params(rest_responses._rsps, "/v2/spaces")
    assert len(queries) == 1
    assert queries[0].get("organization_id") == "Org_acme"


# ── Space create ─────────────────────────────────────────────────────────────


def test_resolve_space_creates_with_organization_id_in_body(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    rest_responses.stub_list("/v2/spaces", "spaces", [])
    rest_responses.stub_post(
        "/v2/spaces",
        response_body={"id": "Space_new", "name": "Fresh"},
        status=201,
    )
    svc = _service(mock_arize_client, logger)

    space_id, status = svc.resolve_space("Org_acme", "Acme Corp", "Fresh")
    assert space_id == "Space_new"
    assert status == "created"
    bodies = _post_bodies(rest_responses._rsps, "/v2/spaces")
    assert bodies == [b'{"name": "Fresh", "organization_id": "Org_acme"}']


def test_dry_run_space_creation_skips_post(
    mock_arize_client, rest_responses: RestResponses, logger: logging.Logger
) -> None:
    rest_responses.stub_list("/v2/organizations", "organizations", [])
    rest_responses.stub_list("/v2/spaces", "spaces", [])
    svc = _service(mock_arize_client, logger, dry_run=True)

    space_id, status = svc.resolve_space("Org_acme", "Acme", "Fresh")
    assert status == "dry_run"
    assert space_id.startswith("__dry_run_space_")
    assert all(c.request.method == "GET" for c in rest_responses.calls)
