"""Diagnose/Scan third-party LLM egress gate (PARSECAT_ALLOW_LLM_EGRESS).

Default-deny: API keys alone must not make Anthropic/OpenAI/OpenRouter
available or selectable. Stub stays local. Opt-in with PARSECAT_ALLOW_LLM_EGRESS=1.
"""
from __future__ import annotations

import pytest

from app.llm import (
    EGRESS_ENV,
    get_llm_client,
    list_providers,
    llm_egress_allowed,
)
from app.llm.stub_client import StubLLMClient


@pytest.fixture(autouse=True)
def _clear_egress_and_keys(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


def test_egress_defaults_to_denied():
    assert llm_egress_allowed() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_egress_truthy_values_allow(monkeypatch, value):
    monkeypatch.setenv(EGRESS_ENV, value)
    assert llm_egress_allowed() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_egress_non_truthy_values_deny(monkeypatch, value):
    monkeypatch.setenv(EGRESS_ENV, value)
    assert llm_egress_allowed() is False


def test_keys_alone_do_not_make_third_party_available(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test")
    providers = {p["id"]: p for p in list_providers()}
    for pid in ("anthropic", "openai", "openai-codex", "openrouter"):
        assert providers[pid]["available"] is False
        assert providers[pid]["disabled_reason"] == "egress_gated"
    assert providers["stub"]["available"] is True


def test_egress_plus_key_makes_provider_available(monkeypatch):
    monkeypatch.setenv(EGRESS_ENV, "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    providers = {p["id"]: p for p in list_providers()}
    assert providers["anthropic"]["available"] is True
    assert providers["anthropic"]["disabled_reason"] is None
    assert providers["openai"]["available"] is False
    assert providers["openai"]["disabled_reason"] == "no_key"


def test_auto_detect_falls_to_stub_when_gate_closed_even_with_keys(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test")
    client = get_llm_client(None)
    assert isinstance(client, StubLLMClient)


def test_explicit_third_party_raises_when_gate_closed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with pytest.raises(RuntimeError, match="LLM egress is disabled"):
        get_llm_client("anthropic")


def test_stub_always_works_when_gate_closed():
    client = get_llm_client("stub")
    assert isinstance(client, StubLLMClient)
