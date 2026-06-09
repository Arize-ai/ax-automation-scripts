"""Exponential-backoff retry for rate-limited GraphQL/REST calls."""

from __future__ import annotations

import logging
import time
from typing import Callable, TypeVar

from .config import INITIAL_BACKOFF, MAX_RETRIES

T = TypeVar("T")


def _is_rate_limit_error(exc: Exception) -> bool:
    """Return True if `exc` looks like a 429 / rate-limit response.

    Heuristic: gql and requests surface rate-limit signals through different
    exception types (TransportQueryError, HTTPError, raw strings, etc.), so we
    sniff the message rather than match a single class.
    """
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "too many requests" in msg


def with_retry(
    fn: Callable[[], T],
    operation_name: str,
    logger: logging.Logger,
) -> T:
    """Call `fn()`, retrying with exponential backoff on rate-limit errors.

    `operation_name` is included in the log line for traceability. Non-rate-limit
    exceptions propagate immediately. Up to `MAX_RETRIES` attempts in total.
    """
    for attempt in range(MAX_RETRIES):
        try:
            return fn()
        # Intentionally broad: gql and requests raise different types for 429s;
        # we only retry when _is_rate_limit_error matches.
        except Exception as exc:
            if _is_rate_limit_error(exc) and attempt < MAX_RETRIES - 1:
                wait = INITIAL_BACKOFF * (2**attempt)
                logger.warning(
                    "Rate limit hit for '%s' (attempt %d/%d). Retrying in %.1fs…",
                    operation_name,
                    attempt + 1,
                    MAX_RETRIES,
                    wait,
                )
                time.sleep(wait)
            else:
                raise
