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

Third-party egress (Anthropic / OpenAI / OpenRouter) is default-deny.
Keys alone do not send a Diagnose/Scan fact bundle off-machine. Set
PARSECAT_ALLOW_LLM_EGRESS=1 (or true/yes/on) to opt in. Stub never leaves
this machine and is always allowed.

`list_providers()` reports which ids are actually usable right now (key
present AND egress allowed for third-party ids), so the frontend's
provider dropdown can show what's real instead of offering an option that
will just error.
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

# Opt-in kill-switch for shipping fact bundles to third-party LLM vendors.
# Unset / false => Diagnose/Scan stay local (stub only), even when API keys
# are present. Required for an honest "we do not send data to AI companies"
# customer letter; disclosure alone is not a stop on send.
EGRESS_ENV = "PARSECAT_ALLOW_LLM_EGRESS"
THIRD_PARTY_PROVIDER_IDS = frozenset({"anthropic", "openai", "openai-codex", "openrouter"})

PROVIDERS = [
    {"id": "anthropic", "label": "Claude (Anthropic)", "requires_env": "ANTHROPIC_API_KEY"},
    {"id": "openai", "label": "GPT (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "openai-codex", "label": "Codex (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "openrouter", "label": "OpenRouter (multi-model gateway)", "requires_env": "OPENROUTER_API_KEY"},
    {"id": "stub", "label": "Stub (no LLM, echoes facts)", "requires_env": None},
]


def llm_egress_allowed() -> bool:
    """True only when PARSECAT_ALLOW_LLM_EGRESS is an explicit truthy value."""
    raw = (os.environ.get(EGRESS_ENV) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


# BYOK's own gate, separate from EGRESS_ENV above and default-OFF (not
# default-on like the rest of this module tries to be permissive once a key
# exists) -- see get_byok_client's docstring for the full reasoning, but in
# short: on a deploy with no auth/ownership model, BYOK is not "a visitor's
# key + their own upload," it's "any visitor's key against any capture_id,"
# since nothing here ties an uploaded capture to the person who uploaded it.
# EGRESS_ENV deliberately does not cover this path (BYOK bypasses it by
# design, for the operator-key-vs-visitor-key consent distinction) -- so
# this is the one gate that actually controls whether BYOK can run at all.
# Flagged by review (PR #83) before this ever reached a public deploy; stays
# off until there's real per-upload ownership, or the host is private.
BYOK_ENV = "PARSECAT_ALLOW_BYOK"


def byok_allowed() -> bool:
    """True only when PARSECAT_ALLOW_BYOK is an explicit truthy value.

    Default-off is the point: a visitor-supplied key must not work on a
    freshly-deployed, zero-config public instance just because the code
    path exists. An operator opts in deliberately, the same shape as
    EGRESS_ENV above, after accepting what that means on a shared,
    unauthenticated capture namespace (see get_byok_client's docstring).
    """
    raw = (os.environ.get(BYOK_ENV) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _egress_gate_error(provider: str) -> RuntimeError:
    return RuntimeError(
        f"LLM egress is disabled for provider {provider!r}: set "
        f"{EGRESS_ENV}=1 to allow Diagnose/Scan fact bundles to leave this "
        f"machine for a third-party model. Stub remains available locally."
    )


def list_providers() -> list[dict]:
    egress = llm_egress_allowed()
    out: list[dict] = []
    for p in PROVIDERS:
        entry = dict(p)
        if p["requires_env"] is None:
            entry["available"] = True
            entry["disabled_reason"] = None
        else:
            has_key = bool(os.environ.get(p["requires_env"]))
            if not egress:
                entry["available"] = False
                # Prefer the gate reason when keys exist so the UI is honest
                # about why a configured provider still cannot send.
                entry["disabled_reason"] = "egress_gated" if has_key else "no_key"
            else:
                entry["available"] = has_key
                entry["disabled_reason"] = None if has_key else "no_key"
        out.append(entry)
    return out


def get_llm_client(provider: str | None = None) -> LLMClient:
    egress = llm_egress_allowed()

    if provider is None:
        if egress and os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif egress and os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        elif egress and os.environ.get("OPENROUTER_API_KEY"):
            provider = "openrouter"
        else:
            provider = "stub"
    elif provider in THIRD_PARTY_PROVIDER_IDS and not egress:
        raise _egress_gate_error(provider)

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


def get_byok_client(api_key: str, model: str | None = None) -> LLMClient:
    """A visitor-supplied OpenRouter key, used for exactly one narration
    call and never persisted (not written to .env, not stored in the DB --
    see reasoning._run_llm, the only caller).

    Gated by BYOK_ENV (default off), checked here rather than only at the
    route layer, so there is exactly one place this can be skipped from.
    Raises when the gate is closed -- callers must not silently fall back
    to Stub, which would look like "your key didn't work" instead of "this
    deployment has not turned this on."

    Correction on an earlier version of this docstring, caught in review
    (PR #83) before this ever reached a public deploy: this was described
    as "a visitor's own key sending their OWN uploaded data" and framed as
    bypassing PARSECAT_ALLOW_LLM_EGRESS on that basis -- that was wrong.
    ParseCat has no auth or upload-ownership model at all: every capture_id
    is readable and diagnose/scan-able by anyone who can reach this API, so
    a visitor's key can request narration of ANY capture on this instance,
    not just one they uploaded. PARSECAT_ALLOW_LLM_EGRESS correctly stays
    irrelevant to that fact (it governs the operator's OWN configured key,
    a different and still-true consent story, #46) -- but BYOK itself
    needed its own gate instead of being treated as automatically fine
    because it's additive. Real fix (per-upload/session ownership, or
    binding to localhost) is tracked separately; this gate is what keeps it
    off by default until one of those lands.

    OpenRouter specifically (not raw Anthropic/OpenAI) so one key format
    covers whichever model family the visitor already has -- see
    DEFAULT_OPENROUTER_MODEL for why this gateway was already the pick for
    "any of 500+ models without a dedicated client per family".
    """
    if not byok_allowed():
        raise RuntimeError(
            f"BYOK is disabled on this deployment: set {BYOK_ENV}=1 to allow "
            f"visitor-supplied keys. Off by default because this app has no "
            f"per-upload ownership model -- a visitor's key could otherwise "
            f"be used to narrate ANY capture on this instance, not just "
            f"their own. Only enable this on a host where that's acceptable "
            f"(e.g. a private/localhost-only deployment)."
        )
    from app.llm.openai_client import OpenAIClient

    resolved_model = (model or "").strip() or DEFAULT_OPENROUTER_MODEL
    return OpenAIClient(model=resolved_model, api_key=api_key, base_url=OPENROUTER_BASE_URL)
