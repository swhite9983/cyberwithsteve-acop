#!/usr/bin/env python3
"""Real connectivity and inference test against the configured Ollama model.

This is deliberately NOT part of the health endpoint. Running a completion
occupies the GPU; doing that on every monitoring scrape would make ACOP's own
health check compete with ACOP's reasoning for the card. This script is the
explicit, operator-initiated version.

What it checks, in order:

1. The Ollama API is reachable and reports its version.
2. The configured model is present, and whether the tag matched exactly.
3. What context length the model declares, versus what ACOP requests.
4. A real completion round-trip, with measured throughput.

Usage:
    python scripts/check_qwen.py
    python scripts/check_qwen.py --prompt "Explain a VLAN in one sentence."

Exit codes:
    0  everything passed
    1  a check failed
    2  configuration problem
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Allow running from a source checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from acop.ai.ollama import OllamaClient
from acop.config import get_settings
from acop.core.exceptions import AcopError

DEFAULT_PROMPT = "Reply with exactly the word READY and nothing else. Do not explain."

PASS = "[ PASS ]"  # noqa: S105 - an output label, not a credential
FAIL = "[ FAIL ]"
WARN = "[ WARN ]"
INFO = "[ INFO ]"


async def run(prompt: str) -> int:
    try:
        settings = get_settings()
    except Exception as exc:
        print(f"{FAIL} Configuration error: {exc}")
        return 2

    print(f"{INFO} Ollama base URL : {settings.ollama_base_url}")
    print(f"{INFO} Configured model: {settings.ollama_model}")
    print(f"{INFO} Requested num_ctx: {settings.ollama_num_ctx}")
    print()

    failures = 0
    warnings = 0

    async with OllamaClient(
        settings.ollama_base_url,
        model=settings.ollama_model,
        control_timeout=settings.ollama_control_timeout_seconds,
        generate_timeout=settings.ollama_generate_timeout_seconds,
        num_ctx=settings.ollama_num_ctx,
        keep_alive=settings.ollama_keep_alive,
    ) as client:
        # 1. Reachability -------------------------------------------------
        try:
            version = await client.version()
            print(f"{PASS} Ollama reachable, server version {version.version}")
        except AcopError as exc:
            print(f"{FAIL} Ollama unreachable: {exc.internal_message}")
            print()
            print("       Check, in order:")
            print("         - Ollama is running on the GPU host")
            print("         - It listens on all interfaces, not just 127.0.0.1")
            print("           (set OLLAMA_HOST=0.0.0.0:11434 in its service unit)")
            print("         - No host firewall or VLAN ACL blocks TCP/11434")
            return 1

        # 2. Model presence ----------------------------------------------
        resolution = await client.resolve_model()
        if not resolution.available:
            print(f"{FAIL} Model {resolution.requested!r} is not on the host.")
            print(f"       Available: {', '.join(resolution.available_models) or 'none'}")
            print(f"       Fix: ollama pull {resolution.requested}")
            failures += 1
        elif not resolution.exact_match:
            print(
                f"{WARN} Model {resolution.requested!r} matched {resolution.resolved!r} "
                "by tag prefix."
            )
            print("       Pin the exact tag in ACOP_OLLAMA_MODEL so that evaluation")
            print("       results and audit records name the model unambiguously.")
            warnings += 1
        else:
            print(f"{PASS} Model {resolution.resolved!r} is present.")

        if failures:
            return 1

        # 3. Declared context length -------------------------------------
        try:
            info = await client.show_model(resolution.resolved)
            declared = info.declared_context_length
            details = info.details
            if details is not None:
                print(
                    f"{INFO} Model build     : "
                    f"{details.parameter_size or 'unknown size'}, "
                    f"{details.quantization_level or 'unknown quantization'}"
                )
            if declared is None:
                print(f"{INFO} Model does not report a context length.")
            elif settings.ollama_num_ctx > declared:
                print(
                    f"{WARN} ACOP requests num_ctx={settings.ollama_num_ctx} but the "
                    f"model declares {declared}."
                )
                warnings += 1
            else:
                pct = settings.ollama_num_ctx / declared * 100
                print(
                    f"{PASS} Context: requesting {settings.ollama_num_ctx} of "
                    f"{declared} available ({pct:.0f}%)."
                )
                if pct < 25:
                    print(
                        "       Later milestones feed retrieved evidence and tool "
                        "output into the prompt."
                    )
                    print(
                        "       Raise ACOP_OLLAMA_NUM_CTX as far as VRAM allows, then "
                        "confirm with nvidia-smi that the model has not spilled to "
                        "system RAM."
                    )
        except AcopError as exc:
            print(f"{WARN} Could not read model metadata: {exc.internal_message}")
            warnings += 1

        # 4. Real inference ----------------------------------------------
        print()
        print(f"{INFO} Running a completion (first call may load the model)...")
        try:
            result = await client.generate(prompt, model=resolution.resolved)
        except AcopError as exc:
            print(f"{FAIL} Inference failed: {exc.internal_message}")
            return 1

        text = result.response.strip()
        preview = text if len(text) <= 200 else text[:200] + "..."
        print(f"{PASS} Completion returned {len(text)} characters.")
        print(f"       Response: {preview!r}")

        if result.total_duration:
            print(f"       Total    : {result.total_duration / 1e9:.2f}s")
        if result.load_duration:
            print(f"       Model load: {result.load_duration / 1e9:.2f}s")
        tps = result.tokens_per_second
        if tps is not None:
            print(f"       Throughput: {tps:.1f} tokens/s ({result.eval_count} tokens)")
            if tps < 5:
                print(
                    f"{WARN} Throughput under 5 tokens/s usually means the model did "
                    "not fit in VRAM and is partly running on CPU."
                )
                print("       Check `nvidia-smi` and `ollama ps` during a request.")
                warnings += 1

    print()
    if failures:
        print(f"{FAIL} {failures} check(s) failed.")
        return 1
    if warnings:
        print(f"{WARN} All checks passed with {warnings} warning(s).")
        return 0
    print(f"{PASS} All checks passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="Prompt to send. Keep it short; this is a connectivity test.",
    )
    args = parser.parse_args()
    return asyncio.run(run(args.prompt))


if __name__ == "__main__":
    raise SystemExit(main())
