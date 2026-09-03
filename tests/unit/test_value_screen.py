"""Predicate-aware secret rejection.

The gap this closes: ``redact()`` masks values whose *mapping key* names a
secret, but in an entity-attribute-value fact table the attribute name is a
*column value*. A fact with predicate ``snmp.community`` and
``value_text = 'public'`` passes the dictionary redactor untouched.
"""

from __future__ import annotations

import pytest

from acop.core.exceptions import SecretRejectedError
from acop.core.redaction import REDACTED
from acop.services.value_screen import (
    MAX_JSON_VALUE_BYTES,
    MAX_TEXT_VALUE_LENGTH,
    FactValueScreen,
)


@pytest.fixture
def screen() -> FactValueScreen:
    return FactValueScreen()


class TestPredicateScreening:
    @pytest.mark.parametrize(
        "predicate",
        [
            "snmp.community",
            "bmc.password",
            "api.token",
            "device.enable_secret",
            "ssh.private_key",
            "auth.credential",
        ],
    )
    def test_secret_bearing_predicates_are_rejected(
        self, screen: FactValueScreen, predicate: str
    ) -> None:
        with pytest.raises(SecretRejectedError):
            screen.screen(predicate, value_text="anything")

    @pytest.mark.parametrize(
        "predicate",
        [
            "network.hostname",
            "memory.total_bytes",
            "config.hash",
            "running_config.sha256",
            "os.version",
            "interface.admin_up",
        ],
    )
    def test_operational_predicates_are_accepted(
        self, screen: FactValueScreen, predicate: str
    ) -> None:
        assert screen.screen(predicate, value_text="x").predicate == predicate

    def test_config_hash_is_not_a_secret(self, screen: FactValueScreen) -> None:
        """Configuration hashes are drift evidence for Milestone 7."""
        assert screen.screen("config.hash", value_text="abc123") is not None

    def test_rejection_is_loud_not_silent(self, screen: FactValueScreen) -> None:
        """A silently-redacted fact would still assert ACOP knows something
        about the asset, which would be false."""
        with pytest.raises(SecretRejectedError) as excinfo:
            screen.screen("snmp.community", value_text="public")
        assert excinfo.value.http_status == 422
        assert excinfo.value.code == "secret_rejected"
        assert excinfo.value.context["predicate"] == "snmp.community"


class TestJsonScreening:
    def test_nested_secret_is_redacted_not_rejected(
        self, screen: FactValueScreen
    ) -> None:
        """The rest of the structure is still legitimate evidence."""
        result = screen.screen(
            "interface.lldp_neighbour",
            value_json={
                "device": "switch-doc-01",
                "port": "Gi1/0/24",
                "credentials": {"username": "acop", "password": "hunter2"},
            },
        )
        assert result.value_json is not None
        rendered = str(result.value_json)
        assert "hunter2" not in rendered
        assert "switch-doc-01" in rendered
        assert result.value_json["credentials"] == REDACTED
        assert result.json_was_redacted
        assert "credentials" in result.redacted_json_keys

    def test_clean_json_passes_through_unchanged(self, screen: FactValueScreen) -> None:
        payload = {"in_errors": 12, "out_errors": 0}
        result = screen.screen("interface.counters", value_json=payload)
        assert result.value_json == payload
        assert not result.json_was_redacted


class TestSizeCaps:
    def test_oversized_text_is_rejected(self, screen: FactValueScreen) -> None:
        with pytest.raises(SecretRejectedError):
            screen.screen("config.running", value_text="x" * (MAX_TEXT_VALUE_LENGTH + 1))

    def test_oversized_json_is_rejected(self, screen: FactValueScreen) -> None:
        payload = {"blob": "y" * (MAX_JSON_VALUE_BYTES + 10)}
        with pytest.raises(SecretRejectedError):
            screen.screen("interface.counters", value_json=payload)

    def test_text_at_the_cap_is_accepted(self, screen: FactValueScreen) -> None:
        assert (
            screen.screen("config.running", value_text="x" * MAX_TEXT_VALUE_LENGTH)
            is not None
        )
