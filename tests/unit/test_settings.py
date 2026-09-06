"""Configuration behaviour."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.engine import make_url

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

    def test_reserved_characters_in_password_round_trip_through_async_url(self) -> None:
        password = "p@ss:word/%?#[]!"
        settings = _settings(
            postgres_host="db.lab",
            postgres_port=5433,
            postgres_user="acop",
            postgres_password=password,
            postgres_db="acopdb",
        )

        parsed = make_url(settings.database_url)

        assert parsed.drivername == "postgresql+asyncpg"
        assert parsed.username == "acop"
        assert parsed.password == password
        assert parsed.host == "db.lab"
        assert parsed.port == 5433
        assert parsed.database == "acopdb"

    def test_reserved_characters_in_password_round_trip_through_sync_url(self) -> None:
        password = "p@ss:word/%?#[]!"
        settings = _settings(
            postgres_host="db.lab",
            postgres_port=5433,
            postgres_user="acop",
            postgres_password=password,
            postgres_db="acopdb",
        )

        parsed = make_url(settings.sync_database_url)

        assert parsed.drivername == "postgresql+psycopg"
        assert parsed.username == "acop"
        assert parsed.password == password
        assert parsed.host == "db.lab"
        assert parsed.port == 5433
        assert parsed.database == "acopdb"

    def test_alembic_url_survives_configparser_interpolation(self) -> None:
        from alembic.config import Config

        password = "p@ss:word/%?#[]!"
        settings = _settings(postgres_password=password)

        assert "%%" in settings.alembic_database_url

        config = Config()
        config.set_main_option("sqlalchemy.url", settings.alembic_database_url)

        decoded = config.get_main_option("sqlalchemy.url")
        parsed = make_url(decoded)

        assert parsed.password == password
        assert decoded == settings.database_url

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


class TestProxmoxSettings:
    """Milestone 5 Checkpoint 1C.

    Every one of these fields is adapter-owned. None of them is reachable from
    a caller: contract rules 9, 10 and 11 refuse at *import* any tool whose
    input schema names a secret, a network locator or a command, so an endpoint
    or a token can only ever arrive from the environment. These tests pin the
    other half of that - that the environment cannot supply a combination which
    is quietly wrong.
    """

    def _enabled(self, **overrides: object) -> Settings:
        base: dict[str, object] = {
            "proxmox_enabled": True,
            "proxmox_instance_id": "homelab-pve",
            "proxmox_base_url": "https://pve.example.invalid:8006",
            "proxmox_token_id": "acop@pve!discovery",
            "proxmox_token_secret": "not-a-real-token",
        }
        base.update(overrides)
        return _settings(**base)

    def test_the_integration_is_off_by_default(self) -> None:
        """An existing deployment is unchanged by this milestone."""
        settings = _settings()
        assert settings.proxmox_enabled is False
        assert settings.proxmox_instance_id == ""
        assert settings.proxmox_base_url == ""
        assert settings.proxmox_token_id == ""
        assert settings.proxmox_token_secret.get_secret_value() == ""

    def test_tls_verification_defaults_on(self) -> None:
        assert _settings().proxmox_verify_tls is True

    def test_a_disabled_integration_needs_no_configuration(self) -> None:
        """The validators must not fire for deployments that do not use this."""
        settings = _settings(proxmox_enabled=False, proxmox_base_url="")
        assert settings.proxmox_enabled is False

    def test_a_complete_configuration_is_accepted(self) -> None:
        settings = self._enabled()
        assert settings.proxmox_instance_id == "homelab-pve"
        assert settings.proxmox_base_url == "https://pve.example.invalid:8006"
        assert settings.proxmox_timeout_seconds > 0

    def test_a_trailing_slash_is_stripped(self) -> None:
        """So that a path is never joined onto a double slash."""
        settings = self._enabled(proxmox_base_url="https://pve.example.invalid:8006/")
        assert settings.proxmox_base_url == "https://pve.example.invalid:8006"

    # -- the invalid combinations ------------------------------------------
    def test_enabled_without_a_base_url_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            self._enabled(proxmox_base_url="")

    def test_enabled_without_a_token_id_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            self._enabled(proxmox_token_id="  ")

    def test_enabled_without_a_token_secret_is_refused(self) -> None:
        """Fail at startup, not on the first sweep at three in the morning."""
        with pytest.raises(ValidationError):
            self._enabled(proxmox_token_secret="")

    def test_plain_http_is_refused(self) -> None:
        """The token travels in a header; http would put it on the wire in clear.

        There is deliberately no development exemption. A self-signed
        certificate is what ``proxmox_verify_tls`` is for; abandoning transport
        security is a different and worse answer to that problem.
        """
        with pytest.raises(ValidationError):
            self._enabled(
                environment=Environment.DEVELOPMENT,
                proxmox_base_url="http://pve.example.invalid:8006",
            )

    @pytest.mark.parametrize("bad", ["", "Homelab", "home lab", "home/lab", "a" * 33])
    def test_a_malformed_instance_id_is_refused(self, bad: str) -> None:
        """It is concatenated into every identifier value written afterwards.

        A slash or a colon in it would make ``<instance>/<vmid>`` ambiguous
        about where the instance ends, and the value is written into rows that
        outlive the configuration.
        """
        with pytest.raises(ValidationError):
            self._enabled(proxmox_instance_id=bad)

    def test_a_disabled_integration_tolerates_a_blank_instance_id(self) -> None:
        assert _settings(proxmox_enabled=False).proxmox_instance_id == ""

    def test_a_non_positive_timeout_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            self._enabled(proxmox_timeout_seconds=0)

    @pytest.mark.parametrize("environment", [Environment.STAGING, Environment.PRODUCTION])
    def test_unverified_tls_is_refused_outside_development(
        self, environment: Environment
    ) -> None:
        """Unverified TLS authenticates nothing - it encrypts to whoever answered."""
        with pytest.raises(ValidationError):
            self._enabled(environment=environment, proxmox_verify_tls=False)

    def test_a_home_lab_may_skip_verification_in_development(self) -> None:
        settings = self._enabled(
            environment=Environment.DEVELOPMENT, proxmox_verify_tls=False
        )
        assert settings.proxmox_verify_tls is False

    # -- secret handling ---------------------------------------------------
    def test_the_token_secret_is_a_secret_str(self) -> None:
        settings = self._enabled(proxmox_token_secret="hunter2-proxmox-token")
        assert settings.proxmox_token_secret.get_secret_value() == (
            "hunter2-proxmox-token"
        )

    def test_the_token_secret_is_not_exposed_by_repr_or_str(self) -> None:
        """The three ways it would leak into a traceback or a log line."""
        secret = "hunter2-proxmox-token"
        settings = self._enabled(proxmox_token_secret=secret)
        assert secret not in repr(settings)
        assert secret not in str(settings)
        assert secret not in repr(settings.proxmox_token_secret)
        assert secret not in str(settings.proxmox_token_secret)

    def test_the_token_id_is_not_hidden(self) -> None:
        """It names a principal rather than proving one.

        Redacting it would only make a misconfigured token harder to diagnose,
        and there is nothing to protect: possession of the id grants nothing.
        """
        settings = self._enabled(proxmox_token_id="acop@pve!discovery")
        assert settings.proxmox_token_id == "acop@pve!discovery"
