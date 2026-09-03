"""Configuration behaviour."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from acop.config import ApiKeyPrincipalConfig, Environment, Settings


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": Environment.TEST,
        "postgres_password": "pw",
        "api_keys": [],
        "auth_enabled": False,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


class TestDatabaseUrl:
    def test_builds_async_url_from_parts(self) -> None:
        settings = _settings(
            postgres_host="db.lab",
            postgres_port=5433,
            postgres_user="acop",
            postgres_password="s3cret",
            postgres_db="acopdb",
        )
        assert settings.database_url == (
            "postgresql+asyncpg://acop:s3cret@db.lab:5433/acopdb"
        )

    def test_safe_target_excludes_credentials(self) -> None:
        settings = _settings(postgres_password="s3cret", postgres_host="db.lab")
        target = settings.safe_database_target
        assert "s3cret" not in target
        assert "db.lab" in target


class TestSecretHandling:
    def test_password_is_not_exposed_in_repr(self) -> None:
        settings = _settings(postgres_password="super-secret-value")
        assert "super-secret-value" not in repr(settings)

    def test_api_key_secret_is_not_exposed_in_repr(self) -> None:
        key = ApiKeyPrincipalConfig(subject="s", secret="hunter2-hunter2")
        assert "hunter2-hunter2" not in repr(key)


class TestOllamaSettings:
    def test_base_url_trailing_slash_is_stripped(self) -> None:
        assert _settings(ollama_base_url="http://gpu:11434/").ollama_base_url == (
            "http://gpu:11434"
        )

    def test_num_ctx_has_an_explicit_default(self) -> None:
        # Regression guard: leaving num_ctx unset makes Ollama silently truncate
        # prompts to its own default, which later reads as hallucination.
        assert _settings().ollama_num_ctx >= 4096

    def test_generate_timeout_exceeds_control_timeout(self) -> None:
        settings = _settings()
        assert (
            settings.ollama_generate_timeout_seconds
            > settings.ollama_control_timeout_seconds
        )


class TestApiKeyParsing:
    def test_parses_json_string(self) -> None:
        settings = _settings(
            auth_enabled=True,
            api_keys=(
                '[{"subject":"acop:user:steve","secret":"abc",'
                '"display_name":"Steve","roles":["admin"]}]'
            ),
        )
        assert len(settings.api_keys) == 1
        assert settings.api_keys[0].subject == "acop:user:steve"
        assert settings.api_keys[0].roles == ["admin"]

    def test_empty_string_yields_no_keys(self) -> None:
        assert _settings(api_keys="").api_keys == []

    def test_duplicate_subjects_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _settings(
                api_keys=[
                    ApiKeyPrincipalConfig(subject="dup", secret="a"),
                    ApiKeyPrincipalConfig(subject="dup", secret="b"),
                ]
            )

    def test_unknown_field_in_key_is_rejected(self) -> None:
        # extra="forbid" catches a typo in .env rather than silently ignoring it.
        with pytest.raises(ValidationError):
            _settings(api_keys='[{"subject":"s","secret":"a","role":["admin"]}]')


class TestEnvironmentGuards:
    def test_production_requires_api_keys_when_auth_enabled(self) -> None:
        with pytest.raises(ValidationError):
            _settings(
                environment=Environment.PRODUCTION,
                auth_enabled=True,
                api_keys=[],
            )

    def test_development_permits_no_api_keys(self) -> None:
        settings = _settings(
            environment=Environment.DEVELOPMENT, auth_enabled=True, api_keys=[]
        )
        assert settings.api_keys == []

    def test_debug_is_rejected_in_production(self) -> None:
        with pytest.raises(ValidationError):
            _settings(
                environment=Environment.PRODUCTION,
                debug=True,
                auth_enabled=False,
            )
