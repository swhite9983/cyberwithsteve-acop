"""Tests against the real Ollama host.

Run with:
    ACOP_TEST_OLLAMA=1 pytest tests/integration/test_live_ollama.py

These read configuration from the environment (or ``.env``), so they exercise
the actual deployment target rather than a fixture. Kept out of the default run
because they occupy the GPU and depend on a machine that may be off.
"""

from __future__ import annotations

import pytest

from acop.ai.ollama import OllamaClient
from acop.config import Settings
from tests.conftest import requires_live_ollama

pytestmark = [pytest.mark.live_ollama, requires_live_ollama]


@pytest.fixture
def live_settings() -> Settings:
    return Settings()


@pytest.fixture
async def live_client(live_settings: Settings):
    async with OllamaClient(
        live_settings.ollama_base_url,
        model=live_settings.ollama_model,
        control_timeout=live_settings.ollama_control_timeout_seconds,
        generate_timeout=live_settings.ollama_generate_timeout_seconds,
        num_ctx=live_settings.ollama_num_ctx,
        keep_alive=live_settings.ollama_keep_alive,
    ) as client:
        yield client


class TestLiveOllama:
    async def test_server_is_reachable(self, live_client: OllamaClient) -> None:
        assert (await live_client.version()).version

    async def test_configured_model_is_present(self, live_client: OllamaClient) -> None:
        resolution = await live_client.resolve_model()
        assert resolution.available, (
            f"Model {resolution.requested!r} is not on the host. "
            f"Available: {resolution.available_models}"
        )

    async def test_completion_round_trip(self, live_client: OllamaClient) -> None:
        result = await live_client.generate(
            "Reply with exactly the word READY and nothing else."
        )
        assert result.done
        assert result.response.strip()

    async def test_declared_context_is_at_least_what_acop_requests(
        self, live_client: OllamaClient, live_settings: Settings
    ) -> None:
        """Catches a silent-truncation misconfiguration.

        Requesting more context than the model declares means Ollama quietly
        discards part of the prompt - which, in later milestones, reads as the
        model ignoring evidence it was given.
        """
        declared = (await live_client.show_model()).declared_context_length
        if declared is None:
            pytest.skip("Model does not report a context length.")
        assert declared >= live_settings.ollama_num_ctx
