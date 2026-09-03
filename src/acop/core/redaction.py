"""Secret redaction for logs and audit records.

Section 23 and 24 of the ACOP design brief require that secrets never reach
logs, audit records, prompts, or the CMDB. Redaction is implemented once, here,
and applied by both the logging pipeline and the audit service so that a future
tool integration cannot accidentally bypass it by writing its own log call.

This is defence in depth, not a substitute for not collecting secrets in the
first place.
"""

from __future__ import annotations

from typing import Any

REDACTED = "***REDACTED***"

#: Substrings that mark a mapping key as secret-bearing. Matched
#: case-insensitively against the key name.
SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "credential",
    "private_key",
    "privatekey",
    "ssh_key",
    "community",  # SNMP community strings
    "enable_secret",
    "session_key",
    "cookie",
)
# Deliberately NOT included: "hash". Configuration hashes are first-class
# evidence for drift detection in Milestone 7 and must remain readable.
# "password_hash" is already covered by the "password" fragment.

#: Depth limit. Protects the logging path from pathological nesting in
#: tool output.
MAX_DEPTH = 12


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` if ``key`` looks like it names a secret."""
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively redact secret-bearing values in a structure.

    Mappings are redacted by key name. Sequences are traversed. Scalars are
    returned unchanged - this function cannot detect a secret that arrives as a
    bare string with no identifying key, which is why tool integrations must
    pass structured parameters rather than pre-formatted strings.
    """
    if _depth >= MAX_DEPTH:
        return "***TRUNCATED***"

    if isinstance(value, dict):
        return {
            key: (REDACTED if is_sensitive_key(str(key)) else redact(item, _depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        redacted = [redact(item, _depth + 1) for item in value]
        return type(value)(redacted) if isinstance(value, tuple) else redacted
    if isinstance(value, set):
        return {redact(item, _depth + 1) for item in value}
    return value
