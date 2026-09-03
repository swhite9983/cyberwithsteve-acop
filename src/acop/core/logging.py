"""Structured logging configuration.

ACOP logs as JSON by default. Three reasons, in order of importance:

1. Milestone 6 ingests ACOP's own logs alongside infrastructure telemetry.
   Parsing free-text logs later is wasted work.
2. Every log line carries the ``request_id`` correlation key automatically.
3. Redaction can be enforced centrally in the processor chain rather than
   trusted to each call site.

``console`` format is available for local development readability.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, cast

import structlog
from structlog.types import EventDict, Processor

from acop.core.correlation import get_request_id
from acop.core.redaction import redact


def _add_request_id(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Attach the current correlation ID to every event."""
    request_id = get_request_id()
    if request_id is not None:
        event_dict.setdefault("request_id", request_id)
    return event_dict


def _rename_logger_name(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Emit the module name under the conventional ``logger`` key."""
    if "logger_name" in event_dict:
        event_dict["logger"] = event_dict.pop("logger_name")
    return event_dict


def _redact_event(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Apply secret redaction to every structured field."""
    # redact() is intentionally Any-typed so it can walk arbitrary tool
    # output; a dict in always yields a dict out.
    return cast(EventDict, redact(event_dict))


def configure_logging(level: str = "INFO", log_format: str = "json") -> None:
    """Configure structlog and route the stdlib logging module through it.

    Args:
        level: Minimum level name, e.g. ``"INFO"``.
        log_format: ``"json"`` for machine-readable output, ``"console"`` for
            human-readable development output.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # structlog-native processors, not the ``structlog.stdlib.*`` variants:
    # those expect a stdlib LogRecord and fail against WriteLoggerFactory. The
    # logger name is bound explicitly by get_logger() instead.
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_request_id,
        _rename_logger_name,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redact_event,
    ]

    if log_format == "console":
        renderer: Processor = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    else:
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route stdlib loggers (uvicorn, sqlalchemy, httpx) through the same sink so
    # that output is uniform and redacted.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )
    for noisy in ("uvicorn.access", "uvicorn.error", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(max(numeric_level, logging.INFO))


def get_logger(name: str | None = None) -> Any:
    """Return a structured logger, with the module name bound as ``logger``.

    The name is passed as an *initial value* rather than via ``.bind()``. This
    matters: modules create their logger at import time, and ``.bind()`` on
    structlog's lazy proxy resolves the active configuration immediately. Since
    imports happen before :func:`configure_logging` runs, binding here would
    permanently freeze every module logger to structlog's default console
    renderer - and a production deployment configured for JSON would quietly
    ship human-formatted lines into its log pipeline. Passing initial values
    keeps the proxy lazy, so the logger picks up whatever configuration is
    active at first use.
    """
    if name:
        # The keyword is ``logger_name`` rather than ``logger`` because
        # structlog.get_logger() forwards keywords to wrap_logger(), whose own
        # first parameter is named ``logger``. A processor renames the field to
        # the conventional ``logger`` on the way out.
        return structlog.get_logger(logger_name=name)
    return structlog.get_logger()
