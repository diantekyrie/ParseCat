"""OpenAI-backed LLMClient, activated when OPENAI_API_KEY is set (and no
ANTHROPIC_API_KEY takes precedence -- see app/llm/__init__.py). Same
contract as AnthropicClient: narrates an already-verified fact bundle, adds
no facts of its own.

Also doubles as the client for any OpenAI-*compatible* gateway (OpenRouter,
a self-hosted LiteLLM proxy, etc.) -- see the "openrouter" provider in
app/llm/__init__.py. Those gateways proxy the standard `chat.completions`
shape for every model they route, including OpenAI's own Codex-family
models, so `base_url`/`api_key` let a caller point this same client at a
gateway instead of api.openai.com without needing a second client class.

Two OpenAI API generations are in play when talking to api.openai.com
directly, and they are NOT interchangeable: regular chat models (gpt-4.1,
etc.) use the `chat.completions` endpoint, but Codex-family models
(gpt-5.x-codex) 404 on that endpoint with "Use the v1/responses endpoint
instead" -- confirmed live against the real API, not assumed. `narrate()`
picks the endpoint by whether "codex" appears in the model name -- but only
when talking to api.openai.com directly (base_url is None). A gateway
never implements that separate stateful /responses endpoint, so a
gateway-routed "codex" model (e.g. OpenRouter's `openai/gpt-5.3-codex`)
must still use the standard chat.completions shape.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient

DEFAULT_MODEL = "gpt-4.1"


class OpenAIClient(LLMClient):
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None, base_url: str | None = None):
        import openai  # imported lazily so the stub/anthropic paths have no hard dependency

        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._client = openai.OpenAI(api_key=resolved_key, base_url=base_url)
        # Respect exactly the model the caller passed -- no env override
        # here. Callers (see app/llm/__init__.py) are responsible for
        # resolving env-based overrides for their own provider id before
        # constructing this client; overriding here too would let a single
        # OPENAI_MODEL env var silently clobber the "openai" and
        # "openai-codex" providers into the same model, defeating having
        # two distinct dropdown options.
        self._model = model
        self._use_responses_api = base_url is None and "codex" in model.lower()

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        if self._use_responses_api:
            response = self._client.responses.create(
                model=self._model,
                instructions=system_prompt,
                input=user_prompt,
            )
            return response.output_text or ""

        response = self._client.chat.completions.create(
            model=self._model,
            # See anthropic_client.py -- same real truncation found live once
            # bundles routinely carry CDM + companiondevice + packet_analysis together.
            max_tokens=8192,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""
