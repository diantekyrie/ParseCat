"""Client selection.

`get_llm_client(provider)` is the only way any caller should get an
LLMClient -- never import a concrete client directly, so swapping/adding
providers stays invisible to callers.

`provider` is an explicit id ("anthropic" | "openai" | "openai-codex" |
"openrouter" | "stub"). Passing None falls back to auto-detection:
ANTHROPIC_API_KEY takes precedence if set, then OPENAI_API_KEY, then
OPENROUTER_API_KEY, otherwise the deterministic stub. "openai-codex" is
never auto-selected -- it's only reachable by explicit choice, same as
today.

`list_providers()` reports which ids are actually usable right now (i.e.
their required env var is set), so the frontend's provider dropdown can
show what's real instead of offering an option that will just error.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient

CODEX_MODEL_ENV = "OPENAI_CODEX_MODEL"
# "gpt-5-codex" (the obvious guess) turned out to be already deprecated per
# a live 404 from the API; confirmed via client.models.list() that the
# current model is "gpt-5.3-codex". Still overridable via env in case this
# drifts again -- OpenAI's codex-family naming has moved fast.
DEFAULT_CODEX_MODEL = "gpt-5.3-codex"

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL_ENV = "OPENROUTER_MODEL"
# OpenRouter model ids are provider-prefixed ("anthropic/...", "openai/...",
# "x-ai/grok-...", "google/..."). This default is just a safe general-purpose
# starting point -- the whole point of routing through OpenRouter is that
# OPENROUTER_MODEL can be pointed at any of the 500+ models it proxies
# (including xAI's Grok) without ParseCat needing a dedicated client or a
# new provider id per model.
DEFAULT_OPENROUTER_MODEL = "anthropic/claude-sonnet-4.5"

PROVIDERS = [
    {"id": "anthropic", "label": "Claude (Anthropic)", "requires_env": "ANTHROPIC_API_KEY"},
    {"id": "openai", "label": "GPT (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "openai-codex", "label": "Codex (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "openrouter", "label": "OpenRouter (multi-model gateway)", "requires_env": "OPENROUTER_API_KEY"},
    {"id": "stub", "label": "Stub (no LLM, echoes facts)", "requires_env": None},
]


def list_providers() -> list[dict]:
    return [
        {**p, "available": p["requires_env"] is None or bool(os.environ.get(p["requires_env"]))}
        for p in PROVIDERS
    ]


def get_llm_client(provider: str | None = None) -> LLMClient:
    if provider is None:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        elif os.environ.get("OPENROUTER_API_KEY"):
            provider = "openrouter"
        else:
            provider = "stub"

    if provider == "anthropic":
        from app.llm.anthropic_client import AnthropicClient
        return AnthropicClient()
    if provider == "openai":
        from app.llm.openai_client import DEFAULT_MODEL, OpenAIClient
        return OpenAIClient(model=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
    if provider == "openai-codex":
        from app.llm.openai_client import OpenAIClient
        return OpenAIClient(model=os.environ.get(CODEX_MODEL_ENV, DEFAULT_CODEX_MODEL))
    if provider == "openrouter":
        from app.llm.openai_client import OpenAIClient
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set")
        model = os.environ.get(OPENROUTER_MODEL_ENV, DEFAULT_OPENROUTER_MODEL)
        return OpenAIClient(model=model, api_key=api_key, base_url=OPENROUTER_BASE_URL)
    if provider == "stub":
        from app.llm.stub_client import StubLLMClient
        return StubLLMClient()

    raise ValueError(f"Unknown LLM provider: {provider!r}")
