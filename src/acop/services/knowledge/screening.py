"""Secret and prompt-injection screening for submitted documents.

**Ordering is the whole design.** Knowledge history is immutable and secrets
must never be stored; together those leave no remediation path, so screening
must complete *before* the first content write. There is exactly one chance,
at ingest.

**Two detectors, two very different policies.**

*Secrets* block. A private key or a Cisco ``enable secret`` in a submitted
document is refused, and neither the content nor the matched value is stored
anywhere - not in a chunk, not in a finding, not in an error body, not in the
audit log. What is stored is a *locator* ("line 412, cols 18-64") and a salted
fingerprint, which is enough for a human to find it in their own copy and
enough for ACOP to recognise the same content on resubmission.

*Prompt injection* does **not** block. That is deliberate and it is worth
stating why, because the opposite instinct is strong: a corpus of security
documentation will eventually contain material *about* prompt injection, which
necessarily contains injection strings. A blocking detector would make ACOP
unable to ingest the very material that teaches it about the threat. The real
control is structural - Milestone 3 executes no tools, the answer schema has no
field that can express a tool call, and retrieved text never occupies the
system role. So injection is flagged, surfaced and audited.

The fingerprint is **salted** so that this table cannot become an
offline-crackable dictionary of the estate's secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Final

from acop.models.knowledge_vocabulary import FindingSeverity, FindingType

DETECTOR_VERSION: Final[str] = "1"

#: Beyond this a submission is refused before anything else happens. Generous
#: for documentation, small enough that nothing enormous reaches the chunker.
MAX_DOCUMENT_BYTES: Final[int] = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Finding:
    """One detector hit. Carries a position, never the matched text."""

    finding_type: FindingType
    severity: FindingSeverity
    detector: str
    detector_version: str
    locator: str
    match_fingerprint: str


@dataclass(frozen=True, slots=True)
class ScreeningReport:
    findings: tuple[Finding, ...] = ()

    @property
    def blocking(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is FindingSeverity.BLOCKING)

    @property
    def advisory(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is FindingSeverity.ADVISORY)

    @property
    def has_blocking(self) -> bool:
        return bool(self.blocking)


@dataclass(frozen=True, slots=True)
class _Detector:
    name: str
    pattern: re.Pattern[str]
    finding_type: FindingType
    severity: FindingSeverity


#: High-confidence secret material. Every one of these is a credential in every
#: context it can appear in, which is what justifies blocking on it.
_SECRET_DETECTORS: Final[tuple[_Detector, ...]] = (
    _Detector(
        "pem_private_key",
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "openssh_private_key",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "cisco_enable_secret",
        re.compile(r"\benable\s+secret\s+\d\s+\$\S+", re.IGNORECASE),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "cisco_type7_password",
        re.compile(r"\bpassword\s+7\s+[0-9A-Fa-f]{8,}"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    _Detector(
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.BLOCKING,
    ),
    # Advisory: an assignment that *might* be a credential. Not blocking,
    # because "password: <your password here>" is ordinary documentation and
    # blocking it would make the screen an obstacle people route around.
    _Detector(
        "credential_assignment",
        re.compile(
            r"\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*"
            r"(?!<|\{|\[|\"?(?:xxx|yyy|redacted|changeme|example|your|placeholder))"
            r"\"?[^\s\"'<>{}]{8,}",
            re.IGNORECASE,
        ),
        FindingType.SECRET_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
)

#: Injection-shaped instructions. All ADVISORY, by design - see the module
#: docstring.
_INJECTION_DETECTORS: Final[tuple[_Detector, ...]] = (
    _Detector(
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?"
            r"(?:previous|prior|above|earlier)\s+"
            r"(?:instructions?|prompts?|rules?|directions?)\b",
            re.IGNORECASE,
        ),
        FindingType.INJECTION_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
    _Detector(
        "role_assertion",
        re.compile(r"^\s*(?:system|assistant)\s*:\s*", re.IGNORECASE | re.MULTILINE),
        FindingType.INJECTION_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
    _Detector(
        "privilege_grant",
        re.compile(
            r"\byou\s+(?:are\s+now|now\s+have|may|must)\b[^.\n]{0,60}\b"
            r"(?:admin|administrator|root|full\s+access|all\s+permissions?|"
            r"unrestricted)\b",
            re.IGNORECASE,
        ),
        FindingType.INJECTION_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
    _Detector(
        "policy_override",
        re.compile(
            r"\b(?:override|bypass|disable)\s+(?:the\s+)?"
            r"(?:system\s+prompt|safety|policy|policies|authorization|"
            r"authorisation|restrictions?)\b",
            re.IGNORECASE,
        ),
        FindingType.INJECTION_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
    _Detector(
        "tool_invocation",
        re.compile(
            r"\b(?:execute|run|invoke|call)\s+(?:the\s+)?"
            r"(?:tool|command|shell|function)\b",
            re.IGNORECASE,
        ),
        FindingType.INJECTION_SUSPECTED,
        FindingSeverity.ADVISORY,
    ),
)


class DocumentScreen:
    """Screens submitted text before any of it is persisted."""

    def __init__(self, fingerprint_salt: str) -> None:
        self._salt = fingerprint_salt.encode("utf-8")

    def fingerprint(self, matched: str) -> str:
        """Salted, keyed hash of a match.

        HMAC rather than a plain digest so the fingerprint set is useless to
        anyone who obtains the database without also obtaining the salt.
        """
        return hmac.new(self._salt, matched.encode("utf-8"), hashlib.sha256).hexdigest()

    def screen(self, text: str) -> ScreeningReport:
        """Run every detector over ``text``.

        Returns findings only. The caller decides what to do with them, and the
        caller is the one thing that may write - which is why this class has no
        database access at all.
        """
        findings: list[Finding] = []
        line_starts = _line_starts(text)

        for detector in (*_SECRET_DETECTORS, *_INJECTION_DETECTORS):
            seen: set[str] = set()
            for match in detector.pattern.finditer(text):
                matched = match.group(0)
                fingerprint = self.fingerprint(matched)
                # One finding per distinct match per detector: a config file
                # with 40 identical type-7 passwords should not produce 40
                # findings a human has to dismiss one at a time.
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                findings.append(
                    Finding(
                        finding_type=detector.finding_type,
                        severity=detector.severity,
                        detector=detector.name,
                        detector_version=DETECTOR_VERSION,
                        locator=_locator(line_starts, match.start(), match.end()),
                        match_fingerprint=fingerprint,
                    )
                )
        return ScreeningReport(findings=tuple(findings))


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, character in enumerate(text):
        if character == "\n":
            starts.append(index + 1)
    return starts


def _locator(line_starts: list[int], start: int, end: int) -> str:
    """Human-findable position. Never includes the matched text."""
    line = _bisect_line(line_starts, start)
    col_start = start - line_starts[line - 1] + 1
    col_end = col_start + (end - start)
    return f"line {line}, cols {col_start}-{col_end}"


def _bisect_line(line_starts: list[int], offset: int) -> int:
    low, high = 0, len(line_starts) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if line_starts[mid] <= offset:
            low = mid
        else:
            high = mid - 1
    return low + 1


@dataclass(frozen=True, slots=True)
class InjectionSummary:
    """Which chunks carry injection-shaped text, for flagging after chunking."""

    ranges: tuple[tuple[int, int], ...] = field(default=())

    def overlaps(self, start: int, end: int) -> bool:
        return any(r_start < end and start < r_end for r_start, r_end in self.ranges)


def injection_ranges(text: str) -> InjectionSummary:
    """Character ranges of injection-shaped matches, for per-chunk flagging."""
    ranges: list[tuple[int, int]] = []
    for detector in _INJECTION_DETECTORS:
        ranges.extend(
            (match.start(), match.end()) for match in detector.pattern.finditer(text)
        )
    return InjectionSummary(ranges=tuple(sorted(ranges)))


__all__ = [
    "DETECTOR_VERSION",
    "MAX_DOCUMENT_BYTES",
    "DocumentScreen",
    "Finding",
    "InjectionSummary",
    "ScreeningReport",
    "injection_ranges",
]
