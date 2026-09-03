"""Async client for the Ollama HTTP API.

ACOP talks to Ollama over its REST API rather than through Open WebUI, so that
the user interface and the inference backend can change independently
(section 3 of the design brief).

Three design points worth stating explicitly:

**Split timeouts.** Control-plane calls (version, tag list) and generation calls
have separate timeouts. A single shared timeout forces a choice between health
checks that block for minutes and generation calls that abort mid-answer.

**Explicit context window.** Ollama applies its own default ``num_ctx`` when the
caller does not set one, and silently truncates the prompt to fit. In a platform
whose whole purpose is reasoning over retrieved evidence, silent truncation is
indistinguishable from hallucination. ``num_ctx`` is therefore sent on every
call.

**Typed failures.** Unreachable, timed out, model missing, and backend error are
four different operational conditions with four different responses. They are
four different exception types, not one generic error.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from acop.ai.ollama.schemas import (
    ChatMessage,
    ChatResponse,
    GenerateResponse,
    ModelInfo,
    OllamaModel,
    OllamaTags,
    OllamaVersion,
)
from acop.core.exceptions import (
    ModelNotAvailableError,
    OllamaError,
    OllamaTimeoutError,
    OllamaUnavailableError,
)
from acop.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ModelResolution:
    """Outcome of resolving a configured model name against the host."""

    requested: str
    resolved: str | None
    available: bool
    available_models: tuple[str, ...] = ()

    @property
    def exact_match(self) -> bool:
        return self.available and self.resolved == self.requested


class OllamaClient:
    """Minimal, typed async client for the subset of Ollama ACOP uses."""

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        control_timeout: float = 5.0,
        generate_timeout: float = 300.0,
        num_ctx: int = 8192,
        keep_alive: str = "10m",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._control_timeout = control_timeout
        self._generate_timeout = generate_timeout
        self._num_ctx = num_ctx
        self._keep_alive = keep_alive
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(
                connect=min(control_timeout, 5.0),
                read=generate_timeout,
                write=control_timeout,
                pool=control_timeout,
            ),
            # ACOP is the only consumer of this connection pool; a small pool is
            # sufficient and keeps idle connections off the GPU host.
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def model(self) -> str:
        return self._model

    @property
    def num_ctx(self) -> int:
        return self._num_ctx

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance owns it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> OllamaClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Request plumbing
    # ------------------------------------------------------------------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        timeout: float,
        json: dict[str, Any] | None = None,
    ) -> Any:
        """Issue a request and translate transport failures into ACOP errors."""
        try:
            response = await self._client.request(
                method,
                path,
                json=json,
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise OllamaTimeoutError(
                f"Ollama did not respond within {timeout}s for {method} {path}",
                context={"path": path, "timeout_seconds": timeout},
            ) from exc
        except httpx.HTTPError as exc:
            # Covers connection refused, DNS failure, TLS failure, and the like.
            raise OllamaUnavailableError(
                f"Could not reach Ollama at {self._base_url}: {type(exc).__name__}",
                context={"path": path, "base_url": self._base_url},
            ) from exc

        if response.status_code >= 400:
            raise OllamaError(
                f"Ollama returned HTTP {response.status_code} for {method} {path}",
                context={
                    "path": path,
                    "status_code": response.status_code,
                    # Bounded: an error body is diagnostic, not a payload.
                    "body_excerpt": response.text[:500],
                },
            )

        try:
            return response.json()
        except ValueError as exc:
            raise OllamaError(
                f"Ollama returned a non-JSON response for {method} {path}",
                context={"path": path},
            ) from exc

    # ------------------------------------------------------------------
    # Control plane
    # ------------------------------------------------------------------
    async def version(self) -> OllamaVersion:
        """Return the Ollama server version."""
        payload = await self._request(
            "GET", "/api/version", timeout=self._control_timeout
        )
        return OllamaVersion.model_validate(payload)

    async def list_models(self) -> list[OllamaModel]:
        """Return the models present on the inference host."""
        payload = await self._request("GET", "/api/tags", timeout=self._control_timeout)
        return OllamaTags.model_validate(payload).models

    async def show_model(self, model: str | None = None) -> ModelInfo:
        """Return metadata for a model, including its declared context length."""
        target = model or self._model
        payload = await self._request(
            "POST",
            "/api/show",
            timeout=self._control_timeout,
            json={"model": target},
        )
        return ModelInfo.model_validate(payload)

    async def resolve_model(self, model: str | None = None) -> ModelResolution:
        """Check whether a model is present, tolerating tag omission.

        ``qwen3`` resolves against a host holding ``qwen3:32b``; the resolved
        tag is returned so that callers log what was actually matched rather
        than what was asked for. An ambiguous prefix resolves to the
        alphabetically first match and is reported as a non-exact match, which
        the health endpoint surfaces as ``degraded`` rather than ``healthy``.
        """
        requested = model or self._model
        models = await self.list_models()
        names = sorted(item.name for item in models)

        if requested in names:
            return ModelResolution(requested, requested, True, tuple(names))

        tagged = f"{requested}:latest"
        if tagged in names:
            return ModelResolution(requested, tagged, True, tuple(names))

        prefixed = [name for name in names if name.startswith(f"{requested}:")]
        if prefixed:
            return ModelResolution(requested, prefixed[0], True, tuple(names))

        return ModelResolution(requested, None, False, tuple(names))

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _options(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        options: dict[str, Any] = {"num_ctx": self._num_ctx}
        if overrides:
            options.update(overrides)
        return options

    async def generate(
        self,
        prompt: str,
        *,
        model: str | None = None,
        system: str | None = None,
        options: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> GenerateResponse:
        """Run a single non-streaming completion.

        Streaming is not implemented in Milestone 1. It is required for a
        responsive UI later, but adding it now would mean building the
        buffering and cancellation semantics before there is anything to stream
        to.
        """
        body: dict[str, Any] = {
            "model": model or self._model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": self._options(options),
        }
        if system is not None:
            body["system"] = system

        started = time.perf_counter()
        payload = await self._request(
            "POST",
            "/api/generate",
            timeout=timeout or self._generate_timeout,
            json=body,
        )
        result = GenerateResponse.model_validate(payload)
        logger.info(
            "ollama.generate.completed",
            model=result.model,
            wall_seconds=round(time.perf_counter() - started, 3),
            eval_count=result.eval_count,
            tokens_per_second=(
                round(result.tokens_per_second, 2)
                if result.tokens_per_second is not None
                else None
            ),
            num_ctx=self._num_ctx,
        )
        return result

    async def chat(
        self,
        messages: list[ChatMessage] | list[dict[str, str]],
        *,
        model: str | None = None,
        options: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> ChatResponse:
        """Run a single non-streaming chat completion."""
        normalised = [
            message.model_dump() if isinstance(message, ChatMessage) else message
            for message in messages
        ]
        payload = await self._request(
            "POST",
            "/api/chat",
            timeout=timeout or self._generate_timeout,
            json={
                "model": model or self._model,
                "messages": normalised,
                "stream": False,
                "keep_alive": self._keep_alive,
                "options": self._options(options),
            },
        )
        return ChatResponse.model_validate(payload)

    async def require_model(self, model: str | None = None) -> str:
        """Return the resolved model tag, raising if it is not present."""
        resolution = await self.resolve_model(model)
        if not resolution.available or resolution.resolved is None:
            raise ModelNotAvailableError(
                f"Model {resolution.requested!r} is not present on {self._base_url}",
                context={
                    "requested_model": resolution.requested,
                    "available_models": list(resolution.available_models),
                },
            )
        return resolution.resolved
