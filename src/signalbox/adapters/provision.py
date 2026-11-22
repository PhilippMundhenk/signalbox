"""Shared helpers of the automatic setup with an admin login (#231, docs/adr/0008).

An integration that sets up its own least-privilege login builds a list of :class:`Step`:
what the step does (shown in the plan, secrets as ``***``), whether it is needed, and the
coroutine that does it. :func:`run_steps` runs the needed ones in order, stops at the first
failure and marks the rest as skipped. Every text that leaves the integration (step details,
messages, errors) goes through a :class:`Redactor` that knows the admin secret and every secret
generated on the way, so a device that echoes a value in an error message cannot leak it.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from signalbox.adapters import AdapterError, SetupStep, StepState

#: Characters of generated passwords: safe in UCI, RouterOS and shell quoting alike.
ALPHABET = string.ascii_letters + string.digits


def new_password(length: int = 32) -> str:
    """A random password (32 of 62 characters: about 190 bits)."""
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


@dataclass
class Redactor:
    """Replaces every known secret in a text with ``***``."""

    values: set[str] = field(default_factory=set)

    def add(self, *values: str | None) -> None:
        for value in values:
            if value:  # short ones too: an unreadable message is better than a leak
                self.values.add(value)

    def __call__(self, text: str) -> str:
        for value in sorted(self.values, key=len, reverse=True):
            text = text.replace(value, "***")
        return text


@dataclass
class Step:
    """One step of a setup: shown as ``SetupStep``, run with ``action`` when ``needed``."""

    id: str
    title: str
    detail: str = ""
    needed: bool = True
    action: Callable[[], Awaitable[str | None]] | None = None
    #: Shown when nothing is needed (why), or after the step ran when it returns no text.
    note: str = ""

    def report(self, redact: Redactor) -> SetupStep:
        return SetupStep(
            id=self.id,
            title=redact(self.title),
            detail=redact(self.detail),
            state=StepState.TODO if self.needed else StepState.UNCHANGED,
            message=redact(self.note),
        )


def plan_steps(steps: Iterable[Step], redact: Redactor) -> list[SetupStep]:
    return [s.report(redact) for s in steps]


async def run_steps(steps: Iterable[Step], redact: Redactor) -> tuple[bool, list[SetupStep]]:
    """Run the needed steps in order; after a failure the rest are skipped."""
    out: list[SetupStep] = []
    failed = False
    for step in steps:
        report = step.report(redact)
        if failed:
            report.state = StepState.SKIPPED if step.needed else StepState.UNCHANGED
        elif step.needed and step.action is not None:
            try:
                message = await step.action()
            except (AdapterError, OSError, TimeoutError) as exc:
                failed = True
                report.state = StepState.FAILED
                report.message = redact(str(exc) or type(exc).__name__)
            else:
                report.state = StepState.DONE
                report.message = redact(message or step.note)
        elif step.needed:
            report.state = StepState.DONE
        out.append(report)
    return not failed, out


def same_fingerprint(a: str | None, b: str | None) -> bool:
    """Fingerprints compared without case, colons, ``SHA256:`` prefix or base64 padding."""
    if not a or not b:
        return False
    return _norm(a) == _norm(b)


def _norm(value: str) -> str:
    text = value.strip()
    if text.upper().startswith("SHA256:"):
        return text[7:].rstrip("=")  # base64 (SSH): case matters
    return "".join(c for c in text.lower() if c in "0123456789abcdef")
