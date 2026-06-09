"""RolesCache — covers TEST_SCENARIOS.md section 5 (5.1–5.5)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from arize_saml_bulk_setup.roles import RolesCache


def _make_response(status: int, payload: dict | None = None) -> MagicMock:
    """Construct a mock Response that mimics requests' raise_for_status behaviour."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    if status >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(
            f"{status} Error", response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    resp.json.return_value = payload or {}
    return resp


def test_resolves_custom_role_by_exact_name(logger: logging.Logger) -> None:
    """5.1: a valid custom role name resolves to its relay ID."""
    cache = RolesCache(api_key="fake", logger=logger)
    response = _make_response(
        200,
        {
            "roles": [
                {"id": "Um9sZTox", "name": "Project Reviewer"},
                {"id": "Um9sZToy", "name": "Project Admin"},
            ],
            "pagination": {"has_more": False},
        },
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", return_value=response
    ) as get:
        rid = cache.resolve_custom_space_role("Project Reviewer")

    assert rid == "Um9sZTox"
    # Cache should only fetch once across multiple lookups
    cache.resolve_custom_space_role("Project Admin")
    assert get.call_count == 1


def test_lookup_is_case_insensitive(logger: logging.Logger) -> None:
    """5.2: 'project reviewer' (lowercased input) matches 'Project Reviewer'."""
    cache = RolesCache(api_key="fake", logger=logger)
    response = _make_response(
        200,
        {
            "roles": [{"id": "Um9sZTox", "name": "Project Reviewer"}],
            "pagination": {"has_more": False},
        },
    )
    with patch("arize_saml_bulk_setup.roles.requests.get", return_value=response):
        assert cache.resolve_custom_space_role("PROJECT reviewer") == "Um9sZTox"


def test_unknown_role_raises_with_available_list(logger: logging.Logger) -> None:
    """5.3: misspelled role surfaces the list of available roles."""
    cache = RolesCache(api_key="fake", logger=logger)
    response = _make_response(
        200,
        {
            "roles": [
                {"id": "Um9sZTox", "name": "Project Reviewer"},
                {"id": "Um9sZToy", "name": "Project Admin"},
            ],
            "pagination": {"has_more": False},
        },
    )
    with patch("arize_saml_bulk_setup.roles.requests.get", return_value=response):
        with pytest.raises(ValueError, match="not found in this account") as exc:
            cache.resolve_custom_space_role("Project Reveiwer")

    assert "project reviewer" in str(exc.value)
    assert "project admin" in str(exc.value)


def test_relay_id_is_passed_through(logger: logging.Logger) -> None:
    """5.4: a caller-supplied relay role ID (Um9sZTo...) is validated against the cache."""
    cache = RolesCache(api_key="fake", logger=logger)
    response = _make_response(
        200,
        {
            "roles": [{"id": "Um9sZToxNQ==", "name": "Project Reviewer"}],
            "pagination": {"has_more": False},
        },
    )
    with patch("arize_saml_bulk_setup.roles.requests.get", return_value=response):
        assert cache.resolve_custom_space_role("Um9sZToxNQ==") == "Um9sZToxNQ=="


def test_429_is_retried_for_real_now(logger: logging.Logger, no_sleep) -> None:
    """5.5: regression — the fix for the prior 429 issue actually retries on rate limit.

    Originally requests.get returned the 429 response without raising, so
    with_retry never saw an exception. raise_for_status now lives inside the
    retry lambda — verify the retry fires.
    """
    cache = RolesCache(api_key="fake", logger=logger)
    bad = _make_response(429)
    good = _make_response(
        200,
        {
            "roles": [{"id": "Um9sZTox", "name": "Project Reviewer"}],
            "pagination": {"has_more": False},
        },
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", side_effect=[bad, good]
    ) as get:
        rid = cache.resolve_custom_space_role("Project Reviewer")

    assert rid == "Um9sZTox"
    assert get.call_count == 2


def test_pagination_loops_until_has_more_false(logger: logging.Logger) -> None:
    """Multi-page /v2/roles response is fully drained."""
    cache = RolesCache(api_key="fake", logger=logger)
    page_1 = _make_response(
        200,
        {
            "roles": [{"id": "Um9sZTox", "name": "Role A"}],
            "pagination": {"has_more": True, "next_cursor": "cursor-2"},
        },
    )
    page_2 = _make_response(
        200,
        {
            "roles": [{"id": "Um9sZToy", "name": "Role B"}],
            "pagination": {"has_more": False},
        },
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", side_effect=[page_1, page_2]
    ):
        assert cache.resolve_custom_space_role("Role A") == "Um9sZTox"
        assert cache.resolve_custom_space_role("Role B") == "Um9sZToy"


# ── ensure_legacy_equivalent_role ─────────────────────────────────────────────


def test_ensure_legacy_equivalent_creates_via_post(logger: logging.Logger) -> None:
    """When the legacy-equivalent role doesn't exist, POST /v2/roles is fired."""
    cache = RolesCache(api_key="fake", logger=logger)
    list_response = _make_response(
        200,
        {"roles": [], "pagination": {"has_more": False}},
    )
    post_response = _make_response(
        201,
        {
            "id": "Um9sZTpBRE1JTg==",
            "name": "Space Admin",
            "is_predefined": False,
        },
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", return_value=list_response
    ), patch(
        "arize_saml_bulk_setup.roles.requests.post", return_value=post_response
    ) as post:
        relay_id, name = cache.ensure_legacy_equivalent_role("admin")

    assert relay_id == "Um9sZTpBRE1JTg=="
    assert name == "Space Admin"
    assert post.call_count == 1
    # Validate the request shape.
    args, kwargs = post.call_args
    body = kwargs["json"]
    assert body["name"] == "Space Admin"
    assert "PROJECT_RESTRICT" in body["permissions"]
    assert "SERVICE_KEY_CREATE" in body["permissions"]
    # Authorization header is set.
    assert kwargs["headers"]["Authorization"] == "Bearer fake"


def test_ensure_legacy_equivalent_is_idempotent(logger: logging.Logger) -> None:
    """Second call for the same legacy key uses the cached relay ID — no second POST."""
    cache = RolesCache(api_key="fake", logger=logger)
    list_response = _make_response(
        200,
        {"roles": [], "pagination": {"has_more": False}},
    )
    post_response = _make_response(
        201, {"id": "Um9sZTpBRE1JTg==", "name": "Space Admin"}
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", return_value=list_response
    ), patch(
        "arize_saml_bulk_setup.roles.requests.post", return_value=post_response
    ) as post:
        first, _ = cache.ensure_legacy_equivalent_role("admin")
        second, _ = cache.ensure_legacy_equivalent_role("admin")

    assert first == second == "Um9sZTpBRE1JTg=="
    assert post.call_count == 1


def test_ensure_legacy_equivalent_short_circuits_when_cached(
    logger: logging.Logger,
) -> None:
    """A role with the canonical name already on the account is reused — no POST."""
    cache = RolesCache(api_key="fake", logger=logger)
    list_response = _make_response(
        200,
        {
            "roles": [
                {"id": "Um9sZTpFWElTVElORw==", "name": "Space Admin"},
            ],
            "pagination": {"has_more": False},
        },
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", return_value=list_response
    ), patch("arize_saml_bulk_setup.roles.requests.post") as post:
        relay_id, name = cache.ensure_legacy_equivalent_role("admin")

    assert relay_id == "Um9sZTpFWElTVElORw=="
    assert name == "Space Admin"
    post.assert_not_called()


def test_ensure_legacy_equivalent_recovers_from_409_race(
    logger: logging.Logger,
) -> None:
    """409 from POST → cache is reloaded and the existing role's ID is returned."""
    cache = RolesCache(api_key="fake", logger=logger)
    first_list = _make_response(
        200,
        {"roles": [], "pagination": {"has_more": False}},
    )
    second_list = _make_response(
        200,
        {
            "roles": [
                {"id": "Um9sZTpSQUNFRA==", "name": "Space Admin"},
            ],
            "pagination": {"has_more": False},
        },
    )
    conflict_response = _make_response(
        409, {"error": "role with name 'Space Admin' already exists"}
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get",
        side_effect=[first_list, second_list],
    ), patch(
        "arize_saml_bulk_setup.roles.requests.post",
        return_value=conflict_response,
    ) as post:
        relay_id, name = cache.ensure_legacy_equivalent_role("admin")

    assert relay_id == "Um9sZTpSQUNFRA=="
    assert name == "Space Admin"
    assert post.call_count == 1


def test_ensure_legacy_equivalent_annotator_minimal_perms(
    logger: logging.Logger,
) -> None:
    """Annotator role posts exactly the minimal queue-annotate permission set."""
    cache = RolesCache(api_key="fake", logger=logger)
    list_response = _make_response(
        200,
        {"roles": [], "pagination": {"has_more": False}},
    )
    post_response = _make_response(
        201, {"id": "Um9sZTpBTk5PVA==", "name": "Space Annotator"}
    )
    with patch(
        "arize_saml_bulk_setup.roles.requests.get", return_value=list_response
    ), patch(
        "arize_saml_bulk_setup.roles.requests.post", return_value=post_response
    ) as post:
        cache.ensure_legacy_equivalent_role("annotator")

    body = post.call_args.kwargs["json"]
    assert body["name"] == "Space Annotator"
    assert sorted(body["permissions"]) == sorted(
        ["QUEUE_READ", "QUEUE_RECORD_READ", "QUEUE_RECORD_ANNOTATE"]
    )


def test_ensure_legacy_equivalent_rejects_unknown_key(
    logger: logging.Logger,
) -> None:
    """Unknown legacy keys raise — guards against typos / new role types."""
    cache = RolesCache(api_key="fake", logger=logger)
    with pytest.raises(ValueError, match="No legacy-equivalent permission set"):
        cache.ensure_legacy_equivalent_role("invalid_role")
