"""Secret redaction.

Section 24 of the design brief forbids secrets in logs, audit records, prompts
and the CMDB. These tests cover the shapes a lab integration actually produces:
device credentials, SNMP community strings, and API tokens nested inside tool
parameters.
"""

from __future__ import annotations

from acop.core.redaction import REDACTED, is_sensitive_key, redact


class TestKeyDetection:
    def test_common_secret_names_are_detected(self) -> None:
        for key in (
            "password",
            "Password",
            "enable_secret",
            "api_key",
            "apiKey",
            "AUTHORIZATION",
            "snmp_community",
            "ssh_key",
            "private_key",
            "session_token",
        ):
            assert is_sensitive_key(key), key

    def test_operational_fields_are_not_redacted(self) -> None:
        for key in ("hostname", "interface", "vlan_id", "status", "username"):
            assert not is_sensitive_key(key), key

    def test_config_hash_is_not_treated_as_a_secret(self) -> None:
        # Configuration hashes are evidence for drift detection in Milestone 7.
        assert not is_sensitive_key("config_hash")
        assert not is_sensitive_key("running_config_sha256")

    def test_password_hash_is_still_redacted(self) -> None:
        assert is_sensitive_key("password_hash")


class TestRedaction:
    def test_flat_mapping(self) -> None:
        result = redact({"user": "acop-svc", "password": "hunter2"})
        assert result == {"user": "acop-svc", "password": REDACTED}

    def test_nested_structures(self) -> None:
        payload = {
            "device": {
                "hostname": "CORE3850",
                "credentials": {"username": "acop", "password": "hunter2"},
            },
            "tools": [
                {"name": "get_switch_vlans", "api_token": "abc123"},
                {"name": "get_switch_interfaces"},
            ],
        }
        result = redact(payload)
        assert result["device"]["hostname"] == "CORE3850"
        assert result["device"]["credentials"] == REDACTED
        assert result["tools"][0]["api_token"] == REDACTED
        assert result["tools"][0]["name"] == "get_switch_vlans"

    def test_snmp_community_string(self) -> None:
        result = redact({"snmp": {"version": "2c", "community": "public"}})
        assert result["snmp"]["community"] == REDACTED
        assert result["snmp"]["version"] == "2c"

    def test_scalars_pass_through(self) -> None:
        assert redact("plain") == "plain"
        assert redact(42) == 42
        assert redact(None) is None

    def test_tuple_type_is_preserved(self) -> None:
        assert redact(("a", "b")) == ("a", "b")

    def test_deep_nesting_is_truncated_rather_than_recursing_forever(self) -> None:
        payload: dict = {}
        node = payload
        for _ in range(50):
            node["child"] = {}
            node = node["child"]
        redact(payload)  # must not raise RecursionError

    def test_original_structure_is_not_mutated(self) -> None:
        original = {"password": "hunter2"}
        redact(original)
        assert original["password"] == "hunter2"
