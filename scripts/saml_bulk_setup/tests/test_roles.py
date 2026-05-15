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
