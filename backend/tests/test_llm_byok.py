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

from app.llm import (
    BYOK_ENV,
    DEFAULT_OPENROUTER_MODEL,
    EGRESS_ENV,
    OPENROUTER_BASE_URL,
    byok_allowed,
    get_byok_client,
)
from app.llm.openai_client import OpenAIClient
from app.services import reasoning


@pytest.fixture(autouse=True)
def _clear_egress_and_keys(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    monkeypatch.delenv(BYOK_ENV, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


# --- BYOK's own gate (default off) --------------------------------------
# Caught in review before this ever reached a public deploy: ParseCat has no
# auth/upload-ownership model, so an ungated BYOK path would let a visitor's
# key narrate ANY capture_id on the instance, not just their own upload.
# BYOK_ENV is the one thing that actually controls whether BYOK can run.

def test_byok_defaults_to_denied():
    assert byok_allowed() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_byok_truthy_values_allow(monkeypatch, value):
    monkeypatch.setenv(BYOK_ENV, value)
    assert byok_allowed() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_byok_non_truthy_values_deny(monkeypatch, value):
    monkeypatch.setenv(BYOK_ENV, value)
    assert byok_allowed() is False


def test_byok_client_raises_when_gate_closed():
    with pytest.raises(RuntimeError, match="BYOK is disabled"):
        get_byok_client("visitor-key-123")


def test_byok_client_points_at_openrouter_with_the_default_model(monkeypatch):
    monkeypatch.setenv(BYOK_ENV, "1")
    client = get_byok_client("visitor-key-123")
    assert isinstance(client, OpenAIClient)
    assert client._model == DEFAULT_OPENROUTER_MODEL
    assert str(client._client.base_url).rstrip("/") == OPENROUTER_BASE_URL


def test_byok_client_respects_an_explicit_model_override(monkeypatch):
    monkeypatch.setenv(BYOK_ENV, "1")
    client = get_byok_client("visitor-key-123", model="x-ai/grok-4")
    assert client._model == "x-ai/grok-4"


def test_byok_client_ignores_blank_model_and_uses_default(monkeypatch):
    monkeypatch.setenv(BYOK_ENV, "1")
    client = get_byok_client("visitor-key-123", model="   ")
    assert client._model == DEFAULT_OPENROUTER_MODEL


def test_byok_bypasses_the_egress_gate_with_no_server_env_configured(monkeypatch):
    # BYOK_ENV (not EGRESS_ENV) is what gates this path -- confirm it still
    # works with EGRESS_ENV unset/false and no server-side key env vars at
    # all, once BYOK_ENV itself is on.
    monkeypatch.setenv(BYOK_ENV, "1")
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


def test_run_llm_treats_whitespace_only_byok_key_as_absent(monkeypatch):
    # Whiskers' review: the frontend trims before sending, but a raw Form
    # POST (or a future non-browser client) could hand this a whitespace-
    # only string -- `if byok_api_key:` alone would treat that as real.
    get_byok_mock = MagicMock(side_effect=AssertionError("should not reach get_byok_client"))
    stub_sentinel = MagicMock()
    stub_sentinel.narrate.return_value = "stub report"
    get_llm_mock = MagicMock(return_value=stub_sentinel)
    monkeypatch.setattr(reasoning, "get_byok_client", get_byok_mock)
    monkeypatch.setattr(reasoning, "get_llm_client", get_llm_mock)

    report, llm_error = reasoning._run_llm(
        {"question": "test"}, "system prompt", provider=None, byok_api_key="   ",
    )

    assert report == "stub report"
    assert llm_error is None
    get_byok_mock.assert_not_called()


def test_run_llm_degrades_gracefully_when_byok_gate_is_closed():
    # End-to-end through the REAL get_byok_client (not mocked): a visitor
    # supplying a key on a deployment that hasn't opted in must get back
    # "narration failed" (bundle/facts still returned by the caller), never
    # an unhandled exception -- same degrade-on-provider-error contract
    # _run_llm already has for a bad key or a provider outage.
    report, llm_error = reasoning._run_llm(
        {"question": "test"}, "system prompt", provider=None,
        byok_api_key="visitor-key-123",
    )
    assert report is None
    assert llm_error is not None
    assert "BYOK is disabled" in llm_error
