"""Shared pytest fixtures.

Keep tests short by centralising the most-reused stubs and sample data here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import responses as responses_lib

from arize_saml_bulk_setup.config import ARIZE_REST_API_URL


@pytest.fixture
def logger() -> logging.Logger:
    """A logger with no handlers — silences output during tests."""
    return logging.getLogger("test")


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_row() -> dict[str, str]:
    """A minimal valid CSV row."""
    return {
        "organization": "Acme Corp",
        "space": "ML Platform",
        "arize_org_role": "member",
        "arize_space_role": "admin",
        "saml_attribute_name": "groups",
        "saml_attribute_value": "arize-ml",
    }


class StubExecutor:
    """A stub `GraphQLExecutor` (see saml.py GraphQLExecutor signature).

    Tests stage per-operation responses by setting `responses[op_name]`
    (either a value or a callable that takes `variables` and returns a value).
    Every invocation is recorded on `.calls` so tests can assert on call shape.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.responses: dict[str, Any] = {}

    def __call__(self, query: Any, variables: dict, op_name: str) -> Any:
        self.calls.append((op_name, variables))
        response = self.responses.get(op_name)
        if callable(response):
            return response(variables)
        return response


@pytest.fixture
def fake_executor() -> StubExecutor:
    return StubExecutor()


@pytest.fixture
def mock_arize_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch the ArizeClient that OrgSpaceService instantiates.

    Without this, OrgSpaceService.__init__ calls ArizeClient(...) which eagerly
    hits the network and 401s with any non-real API key. The toolkit is now
    only used as a GraphQL transport (`_graphql_client`) for SAML operations —
    every org/space op goes through REST instead, mocked by `rest_responses`.
    """
    client = MagicMock(name="ArizeClient")
    client._graphql_client = MagicMock(name="gql_client")

    monkeypatch.setattr(
        "arize_saml_bulk_setup.orgs_spaces.ArizeClient",
        lambda **kwargs: client,
    )
    return client


class RestResponses:
    """Helpers around `responses.RequestsMock` for the Arize REST API.

    Wraps the underlying `responses` mock with sugar for the two endpoint
    shapes we use: paginated lists (`stub_list`) and POST creates (`stub_post`).
    """

    def __init__(self, rsps: responses_lib.RequestsMock) -> None:
        self._rsps = rsps

    def stub_list(
        self,
        path: str,
        items_key: str,
        items: list[dict[str, Any]] | None = None,
        *,
        status: int = 200,
    ) -> None:
        """Register a single-page list response at `GET <ARIZE_REST_API_URL><path>`."""
        self._rsps.add(
            responses_lib.GET,
            f"{ARIZE_REST_API_URL}{path}",
            json={
                items_key: items or [],
                "pagination": {"has_more": False, "next_cursor": None},
            },
            status=status,
        )

    def stub_post(
        self,
        path: str,
        response_body: dict[str, Any] | None = None,
        *,
        status: int = 201,
    ) -> responses_lib.BaseResponse:
        """Register a POST response at `<ARIZE_REST_API_URL><path>`. Returns the
        registered mock so tests can inspect `.call_count`."""
        return self._rsps.add(
            responses_lib.POST,
            f"{ARIZE_REST_API_URL}{path}",
            json=response_body or {},
            status=status,
        )

    @property
    def calls(self) -> Any:
        return self._rsps.calls


@pytest.fixture
def rest_responses() -> Any:
    """Activate `responses` for the duration of the test and yield a RestResponses helper.

    Default behavior: assert_all_requests_are_fired=False so tests don't fail
    when a registered endpoint isn't hit (e.g. dry-run paths skip the API).
    Tests register endpoints they expect to be hit via `stub_list` / `stub_post`.
    """
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield RestResponses(rsps)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip time.sleep inside the retry helper so 429 retry tests run instantly."""
    import arize_saml_bulk_setup.retry as retry_mod

    monkeypatch.setattr(retry_mod.time, "sleep", lambda _seconds: None)
