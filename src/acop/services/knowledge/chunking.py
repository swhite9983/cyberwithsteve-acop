"""Deterministic, heading-aware chunking for Markdown and plain text.

**Determinism is a hard requirement, not a nicety.** Identical input plus
identical parameters must produce byte-identical chunks, because idempotence
proofs and "re-chunk this version the same way in a year" both depend on it.
So: no randomness, no model-assisted splitting, no wall-clock input, and the
parameters that produced a version's chunks are stored alongside it.

**The token limit is real and is not the provider's problem to solve.**
``embeddinggemma:latest`` reports a 2048-token context. Letting the provider
silently truncate would produce a vector that claims to represent a chunk it
only partly read, with nothing anywhere recording that it happened. So the
chunker enforces a ceiling well below the model's, and anything that still
cannot be split is reported rather than quietly trimmed.

Token counts here are an explicit estimate (``chars / 4``) because ACOP has no
tokenizer for the Ollama model. The column is named ``token_estimate`` for the
same reason: a future exact count then *supersedes* a known-approximate value
rather than contradicting one that claimed to be exact.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Final

CHUNKER_NAME: Final[str] = "heading-recursive"
CHUNKER_VERSION: Final[str] = "1"
PARSER_NAME: Final[str] = "markdown-plain"
PARSER_VERSION: Final[str] = "1"

#: Characters per estimated token. Documented, not discovered.
CHARS_PER_TOKEN: Final[int] = 4

DEFAULT_TARGET_TOKENS: Final[int] = 600
DEFAULT_OVERLAP_TOKENS: Final[int] = 80
DEFAULT_MIN_TOKENS: Final[int] = 100
#: Well below embeddinggemma's 2048 so a task prefix and tokenizer variance
#: cannot push a chunk over the provider's ceiling.
DEFAULT_MAX_TOKENS: Final[int] = 1024

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True, slots=True)
class ChunkerParams:
    target_tokens: int = DEFAULT_TARGET_TOKENS
    overlap_tokens: int = DEFAULT_OVERLAP_TOKENS
    min_tokens: int = DEFAULT_MIN_TOKENS
    max_tokens: int = DEFAULT_MAX_TOKENS

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_tokens": self.target_tokens,
            "overlap_tokens": self.overlap_tokens,
            "min_tokens": self.min_tokens,
            "max_tokens": self.max_tokens,
            "chars_per_token": CHARS_PER_TOKEN,
        }


@dataclass(frozen=True, slots=True)
class Chunk:
    ordinal: int
    content: str
    char_start: int
    char_end: int
    token_estimate: int
    heading_path: tuple[str, ...]

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def section_label(self) -> str | None:
        return self.heading_path[-1] if self.heading_path else None


def estimate_tokens(text: str) -> int:
    """Deliberately crude and deliberately named an estimate."""
    return max(1, (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def normalise(raw: str) -> str:
    """Canonical text form. Offsets are recorded against *this*, not the bytes.

    Normalising first is what lets a CRLF-to-LF re-encode be recognised as a
    no-op change rather than a new version of the document.
    """
    text = raw.replace("﻿", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    return text.strip("\n")


@dataclass(frozen=True, slots=True)
class _Section:
    heading_path: tuple[str, ...]
    start: int
    end: int


def _sections(text: str) -> list[_Section]:
    """Split on Markdown headings, tracking the heading path.

    Fenced code blocks are tracked so a ``#`` comment inside a shell example is
    not mistaken for a heading - a real failure mode for network documentation,
    which is full of them.
    """
    lines = text.split("\n")
    offsets: list[int] = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line) + 1

    sections: list[_Section] = []
    path: list[str] = []
    section_start = 0
    in_fence = False
    fence_marker = ""

    for index, line in enumerate(lines):
        fence = _FENCE.match(line)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence = False
            continue
        if in_fence:
            continue

        heading = _HEADING.match(line)
        if not heading:
            continue

        if offsets[index] > section_start:
            sections.append(
                _Section(tuple(path), section_start, min(offsets[index], len(text)))
            )
        depth = len(heading.group(1))
        title = heading.group(2).strip()
        del path[depth - 1 :]
        while len(path) < depth - 1:
            path.append("")
        path.append(title)
        section_start = offsets[index]

    if section_start < len(text):
        sections.append(_Section(tuple(path), section_start, len(text)))
    return [s for s in sections if text[s.start : s.end].strip()]


def _paragraph_spans(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Paragraph boundaries, never splitting inside a fenced code block."""
    body = text[start:end]
    lines = body.split("\n")
    spans: list[tuple[int, int]] = []
    cursor = start
    block_start = start
    in_fence = False
    fence_marker = ""

    for line in lines:
        line_len = len(line) + 1
        fence = _FENCE.match(line)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence = False
        elif not in_fence and not line.strip() and cursor > block_start:
            spans.append((block_start, cursor))
            block_start = cursor + line_len
        cursor += line_len

    if block_start < end:
        spans.append((block_start, end))
    return [(s, e) for s, e in spans if text[s:e].strip()]


def chunk_document(text: str, params: ChunkerParams | None = None) -> list[Chunk]:
    """Split normalised text into ordered, citable chunks.

    The output is a pure function of ``(text, params)``.
    """
    settings = params or ChunkerParams()
    target_chars = settings.target_tokens * CHARS_PER_TOKEN
    max_chars = settings.max_tokens * CHARS_PER_TOKEN
    min_chars = settings.min_tokens * CHARS_PER_TOKEN
    overlap_chars = settings.overlap_tokens * CHARS_PER_TOKEN

    raw: list[tuple[tuple[str, ...], int, int]] = []
    for section in _sections(text):
        buffer_start: int | None = None
        buffer_end = 0
        for para_start, para_end in _paragraph_spans(text, section.start, section.end):
            if buffer_start is None:
                buffer_start, buffer_end = para_start, para_end
                continue
            if para_end - buffer_start <= target_chars:
                buffer_end = para_end
                continue
            raw.append((section.heading_path, buffer_start, buffer_end))
            # Overlap: step back from the end of the emitted chunk so a fact
            # spanning a paragraph boundary is retrievable from either side.
            back = max(buffer_start, buffer_end - overlap_chars)
            buffer_start = min(back, para_start)
            buffer_end = para_end
        if buffer_start is not None:
            raw.append((section.heading_path, buffer_start, buffer_end))

    # Hard-split anything still over the ceiling. This is the guard against
    # silent provider truncation.
    bounded: list[tuple[tuple[str, ...], int, int]] = []
    for heading_path, start, end in raw:
        cursor = start
        while end - cursor > max_chars:
            bounded.append((heading_path, cursor, cursor + max_chars))
            cursor += max_chars
        if end > cursor:
            bounded.append((heading_path, cursor, end))

    # Merge undersized chunks into the previous one when they share a heading.
    merged: list[tuple[tuple[str, ...], int, int]] = []
    for heading_path, start, end in bounded:
        if (
            merged
            and end - start < min_chars
            and merged[-1][0] == heading_path
            and end - merged[-1][1] <= max_chars
        ):
            merged[-1] = (heading_path, merged[-1][1], end)
        else:
            merged.append((heading_path, start, end))

    chunks: list[Chunk] = []
    for heading_path, start, end in merged:
        content = text[start:end].strip("\n")
        if not content.strip():
            continue
        offset = text.index(content, start) if content in text[start:end] else start
        chunks.append(
            Chunk(
                ordinal=len(chunks),
                content=content,
                char_start=offset,
                char_end=offset + len(content),
                token_estimate=estimate_tokens(content),
                heading_path=tuple(p for p in heading_path if p),
            )
        )
    if not chunks and text.strip():
        body = text.strip()
        chunks.append(
            Chunk(
                ordinal=0,
                content=body,
                char_start=text.index(body),
                char_end=text.index(body) + len(body),
                token_estimate=estimate_tokens(body),
                heading_path=(),
            )
        )
    return chunks


__all__ = [
    "CHARS_PER_TOKEN",
    "CHUNKER_NAME",
    "CHUNKER_VERSION",
    "DEFAULT_MAX_TOKENS",
    "PARSER_NAME",
    "PARSER_VERSION",
    "Chunk",
    "ChunkerParams",
    "chunk_document",
    "estimate_tokens",
    "normalise",
]
