"""Shared helpers for saml_bulk_setup API calls."""

from __future__ import annotations

import logging
import time
from typing import Callable, TypeVar

MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0  # seconds

T = TypeVar("T")


def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "too many requests" in msg


def with_retry(
    fn: Callable[[], T],
    operation_name: str,
    logger: logging.Logger,
) -> T:
    """Call fn(), retrying with exponential backoff on rate-limit errors."""
    for attempt in range(MAX_RETRIES):
        try:
            return fn()
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
