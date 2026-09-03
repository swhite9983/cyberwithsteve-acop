"""Ollama inference backend client."""

from acop.ai.ollama.client import ModelResolution, OllamaClient
from acop.ai.ollama.schemas import (
    ChatMessage,
    ChatResponse,
    GenerateResponse,
    ModelInfo,
    OllamaModel,
    OllamaTags,
    OllamaVersion,
)

__all__ = [
    "ChatMessage",
    "ChatResponse",
    "GenerateResponse",
    "ModelInfo",
    "ModelResolution",
    "OllamaClient",
    "OllamaModel",
    "OllamaTags",
    "OllamaVersion",
]
