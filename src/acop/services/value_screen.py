"""Secret screening for CMDB facts.

``acop.core.redaction`` masks values whose *mapping key* names a secret. That
is sufficient for logs and for the audit log's JSONB context, and it is
structurally insufficient for an entity-attribute-value fact table: there the
attribute name lives in the ``predicate`` **column value**, so a fact with
predicate ``snmp.community`` and ``value_text = 'public'`` passes the
dictionary redactor untouched and lands permanently in an append-only table.

This module closes that gap with three checks, applied together:

1. The predicate is screened with the same fragment list.
2. ``value_json`` is passed through :func:`redact`.
3. Values are size-capped, because an oversized blob is neither a useful fact
   nor something anyone will review.

Rejection is loud - :class:`SecretRejectedError` and a DENIED audit record -
rather than silent redaction. A silently-redacted fact would still assert that
ACOP knows something about the asset, which would be false.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from acop.core.exceptions import SecretRejectedError
from acop.core.redaction import REDACTED, is_sensitive_key, redact

#: A fact value longer than this is refused. Generous enough for a Cisco
#: running-config fragment, small enough that nothing enormous accumulates in
#: an append-only table.
MAX_TEXT_VALUE_LENGTH = 64_000

#: Serialised size cap for a JSON value.
MAX_JSON_VALUE_BYTES = 64_000


@dataclass(frozen=True, slots=True)
class ScreenResult:
    """Outcome of screening one fact."""

    predicate: str
    value_json: dict[str, Any] | None
    redacted_json_keys: tuple[str, ...] = ()

    @property
    def json_was_redacted(self) -> bool:
        return bool(self.redacted_json_keys)


def _collect_redacted_keys(original: Any, depth: int = 0) -> list[str]:
    """Names of keys that redaction would mask, for the audit context."""
    found: list[str] = []
    if depth > 12:
        return found
    if isinstance(original, dict):
        for key, value in original.items():
            if is_sensitive_key(str(key)):
                found.append(str(key))
            else:
                found.extend(_collect_redacted_keys(value, depth + 1))
    elif isinstance(original, (list, tuple)):
        for item in original:
            found.extend(_collect_redacted_keys(item, depth + 1))
    return found


class FactValueScreen:
    """Rejects secret-bearing facts before they can be persisted."""

    def screen(
        self,
        predicate: str,
        *,
        value_text: str | None = None,
        value_json: dict[str, Any] | None = None,
    ) -> ScreenResult:
        """Validate one fact's predicate and value.

        Returns the value to persist. ``value_json`` comes back redacted rather
        than rejected when only a nested key is sensitive, because the rest of
        the structure is still legitimate evidence; a sensitive *predicate*
        rejects the whole fact, because then the fact itself is the secret.

        Raises:
            SecretRejectedError: The predicate names a secret, or a value
                exceeds its size cap.
        """
        if is_sensitive_key(predicate):
            raise SecretRejectedError(
                f"Predicate {predicate!r} names a secret and cannot be stored "
                "in the CMDB.",
                context={"predicate": predicate},
            )

        if value_text is not None and len(value_text) > MAX_TEXT_VALUE_LENGTH:
            raise SecretRejectedError(
                f"Text value for {predicate!r} exceeds "
                f"{MAX_TEXT_VALUE_LENGTH} characters.",
                context={"predicate": predicate, "length": len(value_text)},
            )

        if value_json is None:
            return ScreenResult(predicate=predicate, value_json=None)

        import json

        serialised = json.dumps(value_json, default=str)
        if len(serialised.encode("utf-8")) > MAX_JSON_VALUE_BYTES:
            raise SecretRejectedError(
                f"JSON value for {predicate!r} exceeds {MAX_JSON_VALUE_BYTES} bytes.",
                context={"predicate": predicate},
            )

        redacted_keys = tuple(sorted(set(_collect_redacted_keys(value_json))))
        cleaned = redact(value_json)
        if not isinstance(cleaned, dict):  # pragma: no cover - redact preserves dicts
            raise SecretRejectedError(
                f"JSON value for {predicate!r} could not be screened.",
                context={"predicate": predicate},
            )
        return ScreenResult(
            predicate=predicate,
            value_json=cleaned,
            redacted_json_keys=redacted_keys,
        )


__all__ = [
    "MAX_JSON_VALUE_BYTES",
    "MAX_TEXT_VALUE_LENGTH",
    "REDACTED",
    "FactValueScreen",
    "ScreenResult",
]
