"""BEP 31 — Failure Retry Extension.

Provides tracker failure retry semantics per BEP 31.  When a tracker
responds with a ``failure reason`` dictionary that also contains a
``retry in`` field, the client can determine whether the failure is
permanent (``"never"``) or temporary (a positive integer number of
minutes) and schedule retries accordingly.

Examples
--------
>>> from dhtrack.bep31 import parse_failure_response
>>> response = {"failure reason": "Overloaded", "retry in": 5}
>>> parsed = parse_failure_response(response)
>>> parsed.retry_minutes
5
>>> parsed.permanent
False
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FailureRetryInfo:
    """Parsed BEP 31 failure response.

    Attributes
    ----------
    failure_reason : str
        Human-readable failure message from the tracker.
    retry_minutes : int | None
        Number of minutes to wait before retrying.  ``None`` means
        the client should never retry again (equivalent to ``"never"``).
    permanent : bool
        ``True`` if the failure is permanent (retry_minutes is None).
    retry_after : float | None
        Unix timestamp after which a retry may be attempted.  ``None``
        when the failure is permanent or retry_minutes is unspecified.
    """

    failure_reason: str
    retry_minutes: int | None = None
    permanent: bool = False
    retry_after: float | None = None

    def can_retry(self) -> bool:
        """Whether the client should retry this tracker.

        Returns
        -------
        bool
            ``True`` if a retry is allowed (not permanent).
        """
        return not self.permanent

    def seconds_until_retry(self) -> int:
        """Seconds remaining until the next retry is allowed.

        Returns
        -------
        int
            Zero or positive seconds.  If already ready to retry, returns 0.
        """
        if self.retry_after is None:
            return 0
        remaining = int(self.retry_after - time.time())
        return max(0, remaining)


def parse_failure_response(response: dict[bytes, Any]) -> FailureRetryInfo:
    """Parse a bencoded failure response per BEP 31.

    Parameters
    ----------
    response : dict
        The decoded bencoded dictionary from a tracker, expected to
        contain ``"failure reason"`` and optionally ``"retry in"``.

    Returns
    -------
    FailureRetryInfo
        Parsed failure information suitable for scheduling retries.

    Notes
    -----
    Per BEP 31:
    - ``"retry in"`` is either a positive integer (minutes) or the string
      ``"never"``.
    - The ``"failure reason"`` field is always present on error responses.
    """
    reason = response.get(b"failure reason", b"Unknown error")
    if isinstance(reason, bytes):
        reason = reason.decode("utf-8", errors="replace")

    retry_in = response.get(b"retry in")

    if retry_in is None or retry_in == b"never" or retry_in == "never":
        return FailureRetryInfo(
            failure_reason=reason,
            retry_minutes=None,
            permanent=True,
            retry_after=None,
        )

    # Parse integer minutes
    try:
        if isinstance(retry_in, int):
            minutes = retry_in
        elif isinstance(retry_in, str):
            minutes = int(retry_in)
        elif isinstance(retry_in, bytes):
            minutes = int(retry_in.decode("utf-8", errors="replace"))
        else:
            minutes = int(retry_in)
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid 'retry in' value: %s (%r). Treating as permanent failure.", exc, retry_in)
        return FailureRetryInfo(
            failure_reason=reason,
            retry_minutes=None,
            permanent=True,
            retry_after=None,
        )

    if minutes < 0:
        logger.warning("Negative 'retry in' value (%d). Treating as permanent failure.", minutes)
        return FailureRetryInfo(
            failure_reason=reason,
            retry_minutes=None,
            permanent=True,
            retry_after=None,
        )

    retry_after = time.time() + minutes * 60
    return FailureRetryInfo(
        failure_reason=reason,
        retry_minutes=minutes,
        permanent=False,
        retry_after=retry_after,
    )


def should_retry_tracker(
    failure_info: FailureRetryInfo,
    max_retries: int = 5,
    current_attempt: int = 0,
) -> bool:
    """Determine whether a tracker retry should be attempted.

    Parameters
    ----------
    failure_info : FailureRetryInfo
        The parsed BEP 31 failure information.
    max_retries : int, optional
        Maximum number of retry attempts.  Defaults to 5.
    current_attempt : int, optional
        The current retry attempt number (0-based).  Defaults to 0.

    Returns
    -------
    bool
        ``True`` if a retry should be attempted.
    """
    if not failure_info.can_retry():
        return False
    if current_attempt >= max_retries:
        return False
    return True


class TrackerRetryScheduler:
    """Schedules tracker retries based on BEP 31 failure responses.

    Parameters
    ----------
    max_retries : int, optional
        Maximum number of retry attempts before giving up.  Defaults to 5.
    max_delay : int, optional
        Maximum backoff delay in seconds.  Defaults to 3600 (1 hour).

    Attributes
    ----------
    max_retries : int
        Maximum retry attempts.
    max_delay : int
        Maximum backoff delay.
    attempt_count : int
        Number of consecutive failures recorded.
    last_failure : FailureRetryInfo | None
        The most recent parsed failure response.
    """

    def __init__(self, max_retries: int = 5, max_delay: int = 3600) -> None:
        self.max_retries = max_retries
        self.max_delay = max_delay
        self.attempt_count = 0
        self.last_failure: FailureRetryInfo | None = None

    def record_failure(self, response: dict) -> FailureRetryInfo:
        """Record a tracker failure and return retry information.

        Parameters
        ----------
        response : dict
            Bencoded failure response from the tracker.

        Returns
        -------
        FailureRetryInfo
            Parsed failure information.
        """
        self.attempt_count += 1
        self.last_failure = parse_failure_response(response)
        return self.last_failure

    def record_success(self) -> None:
        """Record a successful tracker response, resetting counters."""
        self.attempt_count = 0
        self.last_failure = None

    def should_retry(self) -> bool:
        """Whether another retry should be attempted.

        Returns
        -------
        bool
            ``True`` if retries remain and are not permanent.
        """
        if self.last_failure is None:
            return False
        return should_retry_tracker(self.last_failure, self.max_retries, self.attempt_count)

    def delay_until_ready(self) -> float:
        """Seconds to wait before the next retry.

        Returns the maximum of:
        1. The BEP 31 ``retry_in`` delay (if provided by tracker)
        2. Exponential backoff delay (2^attempt_count seconds, capped at max_delay)

        Returns
        -------
        float
            Seconds to wait.  Zero if no retry is needed.
        """
        bep_delay = 0
        if self.last_failure is not None and self.last_failure.retry_minutes is not None:
            bep_delay = self.last_failure.retry_minutes * 60

        # Exponential backoff
        backoff_delay = min(2**self.attempt_count, self.max_delay)

        return float(max(bep_delay, backoff_delay))

    def reset(self) -> None:
        """Reset all retry state.

        Call after a successful tracker response or when resetting the
        torrent to a clean state.
        """
        self.attempt_count = 0
        self.last_failure = None
