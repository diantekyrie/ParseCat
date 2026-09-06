"""OpenRouter gateway provider (app/llm/__init__.py's "openrouter" id).

Lets a customer reach any model OpenRouter proxies (Anthropic, OpenAI,
xAI/Grok, Google, and 500+ others) through one OPENROUTER_API_KEY, reusing
OpenAIClient pointed at OpenRouter's OpenAI-compatible endpoint instead of
writing a dedicated client. No real network calls here -- these tests only
verify client construction (api_key/base_url/model wiring) and the
endpoint-selection logic, the same boundary the existing openai-codex
endpoint-picking logic sits at.
"""
from __future__ import annotations

import pytest

from app.llm import (
    DEFAULT_OPENROUTER_MODEL,
    OPENROUTER_BASE_URL,
    get_llm_client,
    list_providers,
)
from app.llm.openai_client import OpenAIClient


def test_openrouter_missing_key_raises_a_clear_error(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        get_llm_client("openrouter")


def test_openrouter_client_points_at_the_gateway_with_the_default_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key")
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    client = get_llm_client("openrouter")
    assert isinstance(client, OpenAIClient)
    assert client._model == DEFAULT_OPENROUTER_MODEL
    assert str(client._client.base_url).rstrip("/") == OPENROUTER_BASE_URL


def test_openrouter_model_override_via_env_reaches_any_routed_model(monkeypatch):
    # The whole point: OPENROUTER_MODEL can be pointed at any model
    # OpenRouter proxies, e.g. xAI's Grok, without a new provider id.
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key")
    monkeypatch.setenv("OPENROUTER_MODEL", "x-ai/grok-4")
    client = get_llm_client("openrouter")
    assert client._model == "x-ai/grok-4"


def test_openrouter_is_the_third_auto_detection_fallback(monkeypatch):
    # Case: a customer configures ONLY an OpenRouter key -- no direct
    # Anthropic/OpenAI key. The no-selection default must still reach a
    # real provider, not silently fall back to Stub.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key")
    client = get_llm_client(None)
    assert isinstance(client, OpenAIClient)
    assert str(client._client.base_url).rstrip("/") == OPENROUTER_BASE_URL


def test_openrouter_appears_in_list_providers_with_correct_availability(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    providers = {p["id"]: p for p in list_providers()}
    assert providers["openrouter"]["available"] is False

    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key")
    providers = {p["id"]: p for p in list_providers()}
    assert providers["openrouter"]["available"] is True


def test_gateway_routed_model_never_uses_the_responses_api_even_if_named_codex():
    # Real bug this guards against: OpenRouter's `openai/gpt-5.3-codex`
    # contains "codex" in its name, the same substring the direct-OpenAI
    # path sniffs for to pick the stateful /responses endpoint. Gateways
    # only proxy the standard chat.completions shape for every model they
    # route -- a gateway-routed codex model must NOT flip to /responses.
    gateway_client = OpenAIClient(model="openai/gpt-5.3-codex", api_key="x", base_url=OPENROUTER_BASE_URL)
    assert gateway_client._use_responses_api is False


def test_direct_openai_codex_model_still_uses_the_responses_api():
    # Unchanged existing behavior: no base_url (talking to api.openai.com
    # directly) + "codex" in the model name -> the stateful /responses
    # endpoint, exactly as before this change.
    direct_client = OpenAIClient(model="gpt-5.3-codex", api_key="x")
    assert direct_client._use_responses_api is True
