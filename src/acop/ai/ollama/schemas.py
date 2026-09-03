"""Typed views over the Ollama HTTP API.

Only the fields ACOP actually uses are modelled, with ``extra="allow"`` so that
an Ollama upgrade adding fields does not break parsing. Validating the responses
rather than passing raw dictionaries around means a change in the inference
backend surfaces as a clear validation error at the boundary instead of as a
``KeyError`` inside an agent three milestones later.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OllamaVersion(BaseModel):
    """Response from ``GET /api/version``."""

    model_config = ConfigDict(extra="allow")

    version: str


class ModelDetails(BaseModel):
    """Nested ``details`` object describing a model's build."""

    model_config = ConfigDict(extra="allow", protected_namespaces=())

    family: str | None = None
    parameter_size: str | None = None
    quantization_level: str | None = None


class OllamaModel(BaseModel):
    """A single entry from ``GET /api/tags``."""

    model_config = ConfigDict(extra="allow", protected_namespaces=())

    name: str
    size: int | None = None
    digest: str | None = None
    modified_at: datetime | None = None
    details: ModelDetails | None = None

    @property
    def base_name(self) -> str:
        """Model name without its tag, e.g. ``qwen3`` from ``qwen3:32b``."""
        return self.name.split(":", 1)[0]


class OllamaTags(BaseModel):
    """Response from ``GET /api/tags``."""

    model_config = ConfigDict(extra="allow")

    models: list[OllamaModel] = Field(default_factory=list)


class GenerateResponse(BaseModel):
    """Non-streaming response from ``POST /api/generate``."""

    model_config = ConfigDict(extra="allow", protected_namespaces=())

    model: str
    response: str = ""
    done: bool = False
    created_at: datetime | None = None

    # Nanosecond timings reported by Ollama. Used by the connectivity test and,
    # later, by the evaluation framework in Milestone 19.
    total_duration: int | None = None
    load_duration: int | None = None
    prompt_eval_count: int | None = None
    prompt_eval_duration: int | None = None
    eval_count: int | None = None
    eval_duration: int | None = None

    @property
    def tokens_per_second(self) -> float | None:
        """Generation throughput, or ``None`` if Ollama did not report timings."""
        if not self.eval_count or not self.eval_duration:
            return None
        return self.eval_count / (self.eval_duration / 1_000_000_000)


class ChatMessage(BaseModel):
    """One message in a chat exchange."""

    model_config = ConfigDict(extra="allow")

    role: str
    content: str


class ChatResponse(BaseModel):
    """Non-streaming response from ``POST /api/chat``."""

    model_config = ConfigDict(extra="allow", protected_namespaces=())

    model: str
    message: ChatMessage | None = None
    done: bool = False
    total_duration: int | None = None
    eval_count: int | None = None
    eval_duration: int | None = None


class ModelInfo(BaseModel):
    """Response from ``POST /api/show``."""

    model_config = ConfigDict(extra="allow", protected_namespaces=())

    details: ModelDetails | None = None
    model_info: dict[str, Any] = Field(default_factory=dict)
    parameters: str | None = None
    template: str | None = None

    @property
    def declared_context_length(self) -> int | None:
        """The model's maximum context length, if Ollama reports it.

        Ollama exposes this under an architecture-prefixed key such as
        ``qwen3.context_length``. Reported here so that operators can see the
        gap between what the model supports and what ``ACOP_OLLAMA_NUM_CTX``
        actually requests.
        """
        for key, value in self.model_info.items():
            if key.endswith(".context_length") and isinstance(value, int):
                return value
        return None
