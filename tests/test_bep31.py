"""Tests for BEP 31 — Failure Retry Extension."""

from __future__ import annotations

import time

from dhtrack.bep31 import (
    FailureRetryInfo,
    TrackerRetryScheduler,
    parse_failure_response,
    should_retry_tracker,
)


class TestParseFailureResponse:
    """Tests for parse_failure_response."""

    def test_retry_in_minutes(self):
        """Parse integer retry_in value."""
        response = {b"failure reason": b"Overloaded", b"retry in": 5}
        result = parse_failure_response(response)

        assert result.failure_reason == "Overloaded"
        assert result.retry_minutes == 5
        assert result.permanent is False
        assert result.retry_after is not None

    def test_retry_in_never(self):
        """Parse 'never' retry_in value."""
        response = {b"failure reason": b"Not a tracker", b"retry in": b"never"}
        result = parse_failure_response(response)

        assert result.failure_reason == "Not a tracker"
        assert result.retry_minutes is None
        assert result.permanent is True
        assert result.retry_after is None

    def test_no_retry_in(self):
        """Missing retry_in treated as permanent."""
        response = {b"failure reason": b"Generic error"}
        result = parse_failure_response(response)

        assert result.failure_reason == "Generic error"
        assert result.permanent is True

    def test_retry_in_bytes(self):
        """Parse retry_in as bytes."""
        response = {b"failure reason": b"Error", b"retry in": b"10"}
        result = parse_failure_response(response)

        assert result.failure_reason == "Error"
        assert result.retry_minutes == 10
        assert result.permanent is False

    def test_retry_in_string(self):
        """Parse retry_in as string number."""
        response = {b"failure reason": b"Slow down", b"retry in": b"3"}
        result = parse_failure_response(response)

        assert result.retry_minutes == 3
        assert result.permanent is False

    def test_invalid_retry_in(self):
        """Invalid retry_in treated as permanent."""
        response = {b"failure reason": b"Error", b"retry in": b"abc"}
        result = parse_failure_response(response)

        assert result.permanent is True

    def test_negative_retry_in(self):
        """Negative retry_in treated as permanent."""
        response = {b"failure reason": b"Error", b"retry in": -1}
        result = parse_failure_response(response)

        assert result.permanent is True


class TestFailureRetryInfo:
    """Tests for FailureRetryInfo methods."""

    def test_can_retry_temporary(self):
        """Temporary failure can be retried."""
        info = FailureRetryInfo(
            failure_reason="Overloaded",
            retry_minutes=5,
            permanent=False,
            retry_after=time.time() + 100,
        )
        assert info.can_retry() is True

    def test_can_retry_permanent(self):
        """Permanent failure cannot be retried."""
        info = FailureRetryInfo(
            failure_reason="Not a tracker",
            permanent=True,
        )
        assert info.can_retry() is False

    def test_can_retry_expired(self):
        """Retry after expired timestamp."""
        info = FailureRetryInfo(
            failure_reason="Overloaded",
            retry_minutes=5,
            permanent=False,
            retry_after=time.time() - 100,  # Expired
        )
        assert info.can_retry() is True

    def test_can_retry_not_expired(self):
        """Retry before expired timestamp."""
        info = FailureRetryInfo(
            failure_reason="Overloaded",
            retry_minutes=5,
            permanent=False,
            retry_after=time.time() + 100,  # Not yet
        )
        assert info.can_retry() is True

    def test_seconds_until_retry_zero(self):
        """Return 0 when already ready to retry."""
        info = FailureRetryInfo(
            failure_reason="Overloaded",
            permanent=True,
        )
        assert info.seconds_until_retry() == 0

    def test_seconds_until_retry_positive(self):
        """Return positive seconds when not ready."""
        info = FailureRetryInfo(
            failure_reason="Overloaded",
            retry_minutes=1,
            permanent=False,
            retry_after=time.time() + 120,
        )
        seconds = info.seconds_until_retry()
        assert seconds > 0
        assert seconds <= 120


class TestShouldRetryTracker:
    """Tests for should_retry_tracker function."""

    def test_can_retry_false(self):
        """Return False when can_retry is False."""
        info = FailureRetryInfo(
            failure_reason="Permanent error",
            permanent=True,
        )
        assert should_retry_tracker(info, max_retries=5, current_attempt=0) is False

    def test_max_retries_exceeded(self):
        """Return False when max retries exceeded."""
        info = FailureRetryInfo(
            failure_reason="Temporary error",
            retry_minutes=1,
            permanent=False,
            retry_after=time.time() + 60,
        )
        assert should_retry_tracker(info, max_retries=2, current_attempt=3) is False

    def test_within_retries(self):
        """Return True when within retry limits."""
        info = FailureRetryInfo(
            failure_reason="Temporary error",
            retry_minutes=1,
            permanent=False,
            retry_after=time.time() + 60,
        )
        assert should_retry_tracker(info, max_retries=5, current_attempt=2) is True


class TestTrackerRetryScheduler:
    """Tests for TrackerRetryScheduler class."""

    def test_record_failure(self):
        """Record a failure response."""
        scheduler = TrackerRetryScheduler()
        response = {b"failure reason": b"Overloaded", b"retry in": 5}
        result = scheduler.record_failure(response)

        assert result.failure_reason == "Overloaded"
        assert result.retry_minutes == 5
        assert scheduler.attempt_count == 1

    def test_record_success(self):
        """Record success resets state."""
        scheduler = TrackerRetryScheduler()
        scheduler.record_failure({b"failure reason": b"Error"})
        scheduler.record_success()

        assert scheduler.attempt_count == 0
        assert scheduler.last_failure is None

    def test_should_retry_after_failure(self):
        """Check retry after recording failure."""
        scheduler = TrackerRetryScheduler(max_retries=5)
        scheduler.record_failure({b"failure reason": b"Overloaded", b"retry in": 1})

        assert scheduler.should_retry() is True

    def test_no_retry_permanent(self):
        """No retry for permanent failures."""
        scheduler = TrackerRetryScheduler()
        scheduler.record_failure({b"failure reason": b"Not a tracker", b"retry in": b"never"})

        assert scheduler.should_retry() is False

    def test_delay_minimum_retry_in(self):
        """Delay is at least the BEP 31 retry_in value."""
        scheduler = TrackerRetryScheduler()
        scheduler.record_failure({b"failure reason": b"Overloaded", b"retry in": 2})

        delay = scheduler.delay_until_ready()
        assert delay >= 120  # 2 minutes = 120 seconds

    def test_delay_minimum_backoff(self):
        """Delay uses exponential backoff when no retry_in."""
        scheduler = TrackerRetryScheduler()
        scheduler.record_failure({b"failure reason": b"Generic error"})
        # After 1 failure, backoff is 2^1 = 2 seconds
        scheduler.record_failure({b"failure reason": b"Another error"})
        # After 2 failures, backoff is 2^2 = 4 seconds

        delay = scheduler.delay_until_ready()
        assert delay >= 4  # At least 4 seconds

    def test_delay_max_capped(self):
        """Delay is capped at max_delay."""
        scheduler = TrackerRetryScheduler(max_delay=60)
        for _ in range(10):
            scheduler.record_failure({b"failure reason": b"Error"})

        delay = scheduler.delay_until_ready()
        assert delay <= 60

    def test_reset(self):
        """Reset clears all state."""
        scheduler = TrackerRetryScheduler()
        scheduler.record_failure({b"failure reason": b"Error"})
        scheduler.reset()

        assert scheduler.attempt_count == 0
        assert scheduler.last_failure is None

    def test_attempt_clamping(self):
        """Retry denied when max_retries exceeded."""
        scheduler = TrackerRetryScheduler(max_retries=2)
        scheduler.record_failure({b"failure reason": b"Temp error", b"retry in": 1})
        scheduler.record_failure({b"failure reason": b"Temp error", b"retry in": 1})
        scheduler.record_failure({b"failure reason": b"Temp error", b"retry in": 1})

        # After 3 attempts with max_retries=2, should not retry
        assert scheduler.should_retry() is False
