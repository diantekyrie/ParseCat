"""Real LLM client, activated once ANTHROPIC_API_KEY is set. Not used by
default -- see app/llm/__init__.py for the selection logic.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient

DEFAULT_MODEL = "claude-sonnet-5"


class AnthropicClient(LLMClient):
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        import anthropic  # imported lazily so the stub path has no hard dependency

        # api_key override lets a caller point this at a visitor's own key
        # (BYOK -- see app/llm/__init__.py get_byok_client) instead of this
        # deployment's own ANTHROPIC_API_KEY.
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic(api_key=resolved_key)
        self._model = model

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            # Bundles now routinely carry CDM pairing events, companiondevice
            # associations, and packet_analysis all at once (real gap found
            # live: a genuine investigation-diagnose report was silently cut
            # off mid-sentence at 2048 tokens once packet_analysis started
            # adding real content to summarize).
            max_tokens=8192,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")
