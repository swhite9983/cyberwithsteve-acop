"""Ollama client behaviour.

Mocked at the HTTP layer with respx so the real request construction, response
parsing and error translation are all exercised.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from acop.ai.ollama import OllamaClient
from acop.core.exceptions import (
    ModelNotAvailableError,
    OllamaError,
    OllamaTimeoutError,
    OllamaUnavailableError,
)

BASE_URL = "http://ollama.test:11434"

TAGS_PAYLOAD = {
    "models": [
        {
            "name": "qwen3:32b",
            "size": 20_000_000_000,
            "digest": "abc123",
            "details": {
                "family": "qwen3",
                "parameter_size": "32.8B",
                "quantization_level": "Q4_K_M",
            },
        },
        {"name": "nomic-embed-text:latest", "size": 274_000_000},
    ]
}


def make_client(**overrides: object) -> OllamaClient:
    kwargs: dict[str, object] = {
        "model": "qwen3:32b",
        "control_timeout": 1.0,
        "generate_timeout": 2.0,
        "num_ctx": 8192,
    }
    kwargs.update(overrides)
    return OllamaClient(BASE_URL, **kwargs)  # type: ignore[arg-type]


class TestControlPlane:
    @respx.mock
    async def test_version_is_parsed(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        async with make_client() as client:
            assert (await client.version()).version == "0.5.7"

    @respx.mock
    async def test_list_models_is_parsed(self) -> None:
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        async with make_client() as client:
            models = await client.list_models()
        assert [model.name for model in models] == [
            "qwen3:32b",
            "nomic-embed-text:latest",
        ]
        assert models[0].details is not None
        assert models[0].details.quantization_level == "Q4_K_M"

    @respx.mock
    async def test_unknown_response_fields_do_not_break_parsing(self) -> None:
        # Guards against an Ollama upgrade adding fields.
        payload = {"models": [{"name": "qwen3:32b", "brand_new_field": 1}]}
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=payload)
        )
        async with make_client() as client:
            assert (await client.list_models())[0].name == "qwen3:32b"


class TestModelResolution:
    @respx.mock
    async def test_exact_tag_matches(self) -> None:
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        async with make_client(model="qwen3:32b") as client:
            resolution = await client.resolve_model()
        assert resolution.available
        assert resolution.exact_match
        assert resolution.resolved == "qwen3:32b"

    @respx.mock
    async def test_untagged_name_resolves_by_prefix_but_is_not_exact(self) -> None:
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        async with make_client(model="qwen3") as client:
            resolution = await client.resolve_model()
        assert resolution.available
        assert not resolution.exact_match
        assert resolution.resolved == "qwen3:32b"

    @respx.mock
    async def test_missing_model_is_reported_with_alternatives(self) -> None:
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        async with make_client(model="llama3:70b") as client:
            resolution = await client.resolve_model()
        assert not resolution.available
        assert resolution.resolved is None
        assert "qwen3:32b" in resolution.available_models

    @respx.mock
    async def test_require_model_raises_when_absent(self) -> None:
        respx.get(f"{BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        async with make_client(model="llama3:70b") as client:
            with pytest.raises(ModelNotAvailableError):
                await client.require_model()


class TestGeneration:
    @respx.mock
    async def test_num_ctx_is_always_sent(self) -> None:
        # The whole point: an unset num_ctx makes Ollama truncate silently.
        route = respx.post(f"{BASE_URL}/api/generate").mock(
            return_value=httpx.Response(
                200,
                json={"model": "qwen3:32b", "response": "READY", "done": True},
            )
        )
        async with make_client(num_ctx=16384) as client:
            await client.generate("hello")

        body = route.calls.last.request.content.decode()
        assert '"num_ctx":16384' in body.replace(" ", "")
        assert '"stream":false' in body.replace(" ", "")

    @respx.mock
    async def test_throughput_is_computed_from_reported_timings(self) -> None:
        respx.post(f"{BASE_URL}/api/generate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "model": "qwen3:32b",
                    "response": "READY",
                    "done": True,
                    "eval_count": 40,
                    "eval_duration": 2_000_000_000,
                },
            )
        )
        async with make_client() as client:
            result = await client.generate("hello")
        assert result.tokens_per_second == pytest.approx(20.0)

    @respx.mock
    async def test_throughput_is_none_without_timings(self) -> None:
        respx.post(f"{BASE_URL}/api/generate").mock(
            return_value=httpx.Response(
                200, json={"model": "qwen3:32b", "response": "x", "done": True}
            )
        )
        async with make_client() as client:
            assert (await client.generate("hello")).tokens_per_second is None

    @respx.mock
    async def test_system_prompt_is_forwarded(self) -> None:
        route = respx.post(f"{BASE_URL}/api/generate").mock(
            return_value=httpx.Response(
                200, json={"model": "qwen3:32b", "response": "x", "done": True}
            )
        )
        async with make_client() as client:
            await client.generate("hello", system="You are an SRE.")
        assert "You are an SRE." in route.calls.last.request.content.decode()


class TestErrorTranslation:
    """Four operational conditions must be four distinct exception types."""

    @respx.mock
    async def test_connection_failure_is_unavailable(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(
            side_effect=httpx.ConnectError("refused")
        )
        async with make_client() as client:
            with pytest.raises(OllamaUnavailableError):
                await client.version()

    @respx.mock
    async def test_timeout_is_distinct_from_unavailable(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(side_effect=httpx.ReadTimeout("slow"))
        async with make_client() as client:
            with pytest.raises(OllamaTimeoutError):
                await client.version()

    @respx.mock
    async def test_http_error_status_is_an_ollama_error(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(
            return_value=httpx.Response(500, text="boom")
        )
        async with make_client() as client:
            with pytest.raises(OllamaError) as excinfo:
                await client.version()
        assert excinfo.value.context["status_code"] == 500

    @respx.mock
    async def test_non_json_response_is_an_ollama_error(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, text="<html>proxy error</html>")
        )
        async with make_client() as client:
            with pytest.raises(OllamaError):
                await client.version()

    @respx.mock
    async def test_error_body_is_truncated(self) -> None:
        respx.get(f"{BASE_URL}/api/version").mock(
            return_value=httpx.Response(500, text="x" * 5000)
        )
        async with make_client() as client:
            with pytest.raises(OllamaError) as excinfo:
                await client.version()
        assert len(excinfo.value.context["body_excerpt"]) <= 500


class TestModelInfo:
    @respx.mock
    async def test_declared_context_length_is_extracted(self) -> None:
        respx.post(f"{BASE_URL}/api/show").mock(
            return_value=httpx.Response(
                200,
                json={
                    "details": {"family": "qwen3"},
                    "model_info": {
                        "general.architecture": "qwen3",
                        "qwen3.context_length": 40960,
                        "qwen3.embedding_length": 5120,
                    },
                },
            )
        )
        async with make_client() as client:
            info = await client.show_model()
        assert info.declared_context_length == 40960

    @respx.mock
    async def test_missing_context_length_returns_none(self) -> None:
        respx.post(f"{BASE_URL}/api/show").mock(
            return_value=httpx.Response(200, json={"model_info": {}})
        )
        async with make_client() as client:
            assert (await client.show_model()).declared_context_length is None
