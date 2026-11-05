"""#98: a "[redacted-*]" token must never support a same/different-entity
conclusion in narration.

#96 redacts PII in stored free text at persist, replacing values with typed
tokens ("[redacted-email]", "[redacted-account]", etc). Nothing in the
prompts told the narrator those tokens carry no identity information, so
nothing stopped it from treating two facts that both show
"[redacted-account]" as the same account. These tests pin the prompt rule
and that the token reaches the LLM layer verbatim, unmolested by any
code-level merging/deduping before narration.
"""
from __future__ import annotations

from app.services import reasoning
from app.services.reasoning import (
    INVESTIGATION_SYSTEM_PROMPT, SCAN_SYSTEM_PROMPT, SYSTEM_PROMPT, _run_llm,
)

_RULE_MARKER = "NOT an identifier"


def test_redacted_token_rule_is_in_the_base_system_prompt():
    assert _RULE_MARKER in SYSTEM_PROMPT
    assert "same-entity" in SYSTEM_PROMPT
    assert "[redacted-" in SYSTEM_PROMPT


def test_redacted_token_rule_is_inherited_by_scan_and_investigation_prompts():
    # Both are SYSTEM_PROMPT + extra rules, so the base rule must survive.
    assert _RULE_MARKER in SCAN_SYSTEM_PROMPT
    assert _RULE_MARKER in INVESTIGATION_SYSTEM_PROMPT


def test_two_different_redacted_accounts_reach_narration_verbatim_and_distinct(monkeypatch):
    # Two crash facts, each naming a DIFFERENT real account that both
    # happened to redact to the identical token. The pipeline must not
    # collapse or editorialize them before the narrator sees them -- the
    # token itself is the only thing that should appear, twice, unchanged.
    bundle = {
        "question": "were there any login failures?",
        "crashes": [
            {"message": "login failed for [redacted-account]", "package": "com.example.a"},
            {"message": "login failed for [redacted-account]", "package": "com.example.b"},
        ],
    }
    report, llm_error, narrated_by = _run_llm(bundle, SYSTEM_PROMPT, provider="stub")
    assert llm_error is None
    assert narrated_by == "stub"
    assert report.count("[redacted-account]") == 2
    # Both packages still appear distinctly -- the token didn't get
    # deduped or merged into a single "account" before reaching narration.
    assert "com.example.a" in report
    assert "com.example.b" in report
