"""Caller mistakes with a stable code and a short hint.

EXPERIMENTAL PROPOSAL — not part of the stable dhtrack API.
"""

from __future__ import annotations


class ToolError(Exception):
    """A tool refused the call. ``code`` is stable; ``hint`` says the next step."""

    def __init__(self, message: str, *, code: str = "invalid_argument", hint: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.hint = hint

    def to_dict(self) -> dict[str, object]:
        """JSON-ready error. Agents should branch on ``code``, not on the sentence."""
        payload: dict[str, object] = {"error": str(self), "code": self.code}
        if self.hint:
            payload["hint"] = self.hint
        return payload
