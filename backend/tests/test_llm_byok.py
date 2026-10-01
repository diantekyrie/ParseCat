"""Visitor-supplied ("bring your own key") OpenRouter access.

Lets a public deploy with NO server-side LLM key configured still offer
real narration to a visitor who pastes in their own OpenRouter key, while
everyone else gets Stub (see app/llm/__init__.py get_byok_client's
docstring for why this is a distinct consent path from the operator's own
PARSECAT_ALLOW_LLM_EGRESS gate, not a bypass of it). No real network calls
here -- same boundary as test_llm_openrouter_gateway.py: construction and
dispatch-priority only.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.llm import DEFAULT_OPENROUTER_MODEL, EGRESS_ENV, OPENROUTER_BASE_URL, get_byok_client
from app.llm.openai_client import OpenAIClient
from app.services import reasoning


@pytest.fixture(autouse=True)
def _clear_egress_and_keys(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


def test_byok_client_points_at_openrouter_with_the_default_model():
    client = get_byok_client("visitor-key-123")
    assert isinstance(client, OpenAIClient)
    assert client._model == DEFAULT_OPENROUTER_MODEL
    assert str(client._client.base_url).rstrip("/") == OPENROUTER_BASE_URL


def test_byok_client_respects_an_explicit_model_override():
    client = get_byok_client("visitor-key-123", model="x-ai/grok-4")
    assert client._model == "x-ai/grok-4"


def test_byok_client_ignores_blank_model_and_uses_default():
    client = get_byok_client("visitor-key-123", model="   ")
    assert client._model == DEFAULT_OPENROUTER_MODEL


def test_byok_bypasses_the_egress_gate_with_no_server_env_configured():
    # The whole point: this must succeed with EGRESS_ENV unset/false and no
    # server-side key env vars at all -- a public deploy with nothing
    # configured still has to be able to construct a BYOK client.
    client = get_byok_client("visitor-key-123")
    assert isinstance(client, OpenAIClient)


def test_run_llm_prefers_byok_over_the_provider_dropdown(monkeypatch):
    # Even when a (gated, unavailable) `provider` is also passed, a supplied
    # byok_api_key must win -- see reasoning._run_llm's dispatch comment.
    byok_sentinel = MagicMock()
    byok_sentinel.narrate.return_value = "byok report"
    get_byok_mock = MagicMock(return_value=byok_sentinel)
    get_llm_mock = MagicMock(side_effect=AssertionError("should not reach get_llm_client"))
    monkeypatch.setattr(reasoning, "get_byok_client", get_byok_mock)
    monkeypatch.setattr(reasoning, "get_llm_client", get_llm_mock)

    report, llm_error = reasoning._run_llm(
        {"question": "test"}, "system prompt", provider="anthropic",
        byok_api_key="visitor-key", byok_model="some/model",
    )

    assert report == "byok report"
    assert llm_error is None
    get_byok_mock.assert_called_once_with("visitor-key", "some/model")
    get_llm_mock.assert_not_called()


def test_run_llm_falls_back_to_provider_dispatch_without_a_byok_key(monkeypatch):
    get_byok_mock = MagicMock(side_effect=AssertionError("should not reach get_byok_client"))
    stub_sentinel = MagicMock()
    stub_sentinel.narrate.return_value = "stub report"
    get_llm_mock = MagicMock(return_value=stub_sentinel)
    monkeypatch.setattr(reasoning, "get_byok_client", get_byok_mock)
    monkeypatch.setattr(reasoning, "get_llm_client", get_llm_mock)

    report, llm_error = reasoning._run_llm({"question": "test"}, "system prompt", provider=None)

    assert report == "stub report"
    assert llm_error is None
    get_llm_mock.assert_called_once_with(None)
    get_byok_mock.assert_not_called()
