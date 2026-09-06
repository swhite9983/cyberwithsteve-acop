"""What is allowed to leave the adapter boundary.

An adapter returns whatever it returns. What ACOP *stores* and *shows* is an
allow-list: only the fields the tool's ``output_model`` declares, or the
narrower ``output_allow_list`` where a tool names one.

**Constructed, not filtered.** A new dictionary is built from the permitted
names rather than the returned one being stripped of forbidden ones. The
difference matters the first time an adapter returns a key nobody anticipated:
a deny-list lets it through, an allow-list does not. This is the same technique
:data:`~acop.models.tool_vocabulary.ERROR_PHRASES` uses for error text.

M1's :func:`~acop.core.redaction.redact` is then applied as defence in depth.
For a correctly declared tool it changes nothing - a field named ``api_key``
could not be in the output model, because import rule 12 forbids additional
properties and rule 9's spirit applies to what a tool is designed to return. If
it ever *does* change something, that is a bug in a declaration, and a test
asserts it is a no-op for every catalog tool's sample output.
"""

from __future__ import annotations

from typing import Any

from acop.core.logging import get_logger
from acop.core.redaction import is_sensitive_key, redact
from acop.tools.contract import ToolDefinition
from acop.tools.envelope import digest_of

logger = get_logger(__name__)


def sanitize_output(
    definition: ToolDefinition, payload: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Return the storable output and its digest.

    Returns:
        The allow-listed, redacted payload, and a SHA-256 over its canonical
        form. The digest is taken over the *sanitized* value, because that is
        what was stored - a digest over something nobody kept could not be
        checked against anything.
    """
    permitted = definition.effective_output_fields()
    dropped = sorted(set(payload) - set(permitted))
    if dropped:
        # Not an error: an adapter may legitimately return more than a tool
        # chose to publish. Logged because a surprise here is worth seeing.
        logger.info(
            "tools.output.fields_dropped",
            tool=definition.qualified_name,
            dropped=dropped,
        )
    clean = {name: payload[name] for name in sorted(permitted) if name in payload}

    suspicious = [name for name in clean if is_sensitive_key(name)]
    if suspicious:
        # A declared output field whose name reads as a secret is a declaration
        # defect. Redaction below still covers it, but silence would not.
        logger.error(
            "tools.output.sensitive_field_declared",
            tool=definition.qualified_name,
            fields=sorted(suspicious),
        )

    redacted: dict[str, Any] = redact(clean)
    return redacted, digest_of(redacted)


__all__ = ["sanitize_output"]
