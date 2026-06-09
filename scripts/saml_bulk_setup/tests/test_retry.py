"""with_retry behaviour — covers TEST_SCENARIOS.md section 4 (4.1–4.3)."""

from __future__ import annotations

import logging

import pytest

from arize_saml_bulk_setup.config import MAX_RETRIES
from arize_saml_bulk_setup.retry import _is_rate_limit_error, with_retry


def test_retries_once_on_429_then_succeeds(
    logger: logging.Logger, no_sleep, caplog: pytest.LogCaptureFixture
) -> None:
    """4.1: a transient 429 triggers exactly one retry and then succeeds."""
    attempts = {"n": 0}

    def fn() -> str:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("429 Too Many Requests")
        return "ok"

    with caplog.at_level(logging.WARNING, logger="test"):
        result = with_retry(fn, "op", logger)

    assert result == "ok"
    assert attempts["n"] == 2
    assert any("Rate limit hit" in rec.message for rec in caplog.records)


def test_gives_up_after_max_retries(logger: logging.Logger, no_sleep) -> None:
    """4.2: MAX_RETRIES consecutive 429s eventually surface the error."""
    attempts = {"n": 0}

    def fn() -> str:
        attempts["n"] += 1
        raise RuntimeError("HTTP 429")

    with pytest.raises(RuntimeError, match="429"):
        with_retry(fn, "op", logger)

    assert attempts["n"] == MAX_RETRIES


def test_non_rate_limit_error_does_not_retry(logger: logging.Logger) -> None:
    """4.3: a non-rate-limit error surfaces immediately, no retry."""
    attempts = {"n": 0}

    def fn() -> str:
        attempts["n"] += 1
        raise ValueError("something else broke")

    with pytest.raises(ValueError, match="something else broke"):
        with_retry(fn, "op", logger)

    assert attempts["n"] == 1


@pytest.mark.parametrize(
    "message",
    [
        "429 Too Many Requests",
        "Rate limit exceeded",
        "HTTP 429",
        "Too Many Requests",
    ],
)
def test_is_rate_limit_error_matches_known_messages(message: str) -> None:
    assert _is_rate_limit_error(RuntimeError(message)) is True


@pytest.mark.parametrize(
    "message",
    ["500 Internal Server Error", "connection refused", "ValueError boom"],
)
def test_is_rate_limit_error_rejects_other_errors(message: str) -> None:
    assert _is_rate_limit_error(RuntimeError(message)) is False
