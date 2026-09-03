"""Structured logging configuration.

The regression guarded here was found by running the real server rather than by
reading the code: module-level loggers were resolving structlog's configuration
at import time, so a deployment configured for JSON emitted console-formatted
lines instead. Nothing about the code looked wrong - only the output did.
"""

from __future__ import annotations

import json

import pytest
import structlog

from acop.core.correlation import reset_request_id, set_request_id
from acop.core.logging import configure_logging, get_logger


@pytest.fixture(autouse=True)
def _reset_structlog():
    yield
    structlog.reset_defaults()


class TestLoggerBindingOrder:
    def test_logger_created_before_configuration_still_honours_it(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The import-order regression.

        A module writes ``logger = get_logger(__name__)`` at import time, which
        is before configure_logging() runs. The logger must still emit in the
        configured format.
        """
        structlog.reset_defaults()
        logger = get_logger("acop.test.module")  # created first, on purpose

        configure_logging(level="INFO", log_format="json")

        logger.info("ordering.check", detail="value")

        line = capsys.readouterr().out.strip().splitlines()[-1]
        payload = json.loads(line)  # would raise on console-formatted output
        assert payload["event"] == "ordering.check"
        assert payload["logger"] == "acop.test.module"
        assert payload["detail"] == "value"
        assert payload["level"] == "info"

    def test_console_format_is_not_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        structlog.reset_defaults()
        logger = get_logger("acop.test.module")
        configure_logging(level="INFO", log_format="console")
        logger.info("console.check")
        out = capsys.readouterr().out
        assert "console.check" in out
        with pytest.raises(json.JSONDecodeError):
            json.loads(out.strip().splitlines()[-1])


class TestLogContent:
    def test_correlation_id_is_attached_automatically(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        structlog.reset_defaults()
        configure_logging(level="INFO", log_format="json")
        token = set_request_id("req-logging-1")
        try:
            get_logger("acop.test").info("correlated.event")
        finally:
            reset_request_id(token)
        payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert payload["request_id"] == "req-logging-1"

    def test_secrets_are_redacted_in_log_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        structlog.reset_defaults()
        configure_logging(level="INFO", log_format="json")
        get_logger("acop.test").info(
            "device.connect",
            hostname="CORE3850",
            password="hunter2",
            snmp_community="public",
        )
        line = capsys.readouterr().out.strip().splitlines()[-1]
        assert "hunter2" not in line
        assert "public" not in line
        assert "CORE3850" in line

    def test_timestamps_are_utc_iso8601(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Incident timelines correlate ACOP events with Prometheus and syslog.
        # A local-time or naive timestamp makes that correlation quietly wrong.
        structlog.reset_defaults()
        configure_logging(level="INFO", log_format="json")
        get_logger("acop.test").info("timestamp.check")
        payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert payload["timestamp"].endswith("Z")


class TestLevelFiltering:
    def test_below_threshold_events_are_dropped(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        structlog.reset_defaults()
        configure_logging(level="WARNING", log_format="json")
        logger = get_logger("acop.test")
        logger.info("should.not.appear")
        logger.warning("should.appear")
        out = capsys.readouterr().out
        assert "should.not.appear" not in out
        assert "should.appear" in out
