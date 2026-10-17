"""Client selection.

`get_llm_client(provider)` is the only way any caller should get an
LLMClient -- never import a concrete client directly, so swapping/adding
providers stays invisible to callers.

`provider` is an explicit id ("anthropic" | "openai" | "openai-codex" |
"grok" | "openrouter" | "stub"). Passing None falls back to auto-detection:
ANTHROPIC_API_KEY takes precedence if set, then OPENAI_API_KEY, then
XAI_API_KEY, then OPENROUTER_API_KEY, otherwise the deterministic stub.
"openai-codex" is never auto-selected -- it's only reachable by explicit
choice, same as today.

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

# xAI's API is OpenAI-compatible (same chat.completions request/response
# shape), so this reuses OpenAIClient with a different base_url rather than
# a dedicated client class -- same pattern as the "openrouter" provider.
XAI_BASE_URL = "https://api.x.ai/v1"
XAI_MODEL_ENV = "XAI_MODEL"
DEFAULT_GROK_MODEL = "grok-4"

# Opt-in kill-switch for shipping fact bundles to third-party LLM vendors.
# Unset / false => Diagnose/Scan stay local (stub only), even when API keys
# are present. Required for an honest "we do not send data to AI companies"
# customer letter; disclosure alone is not a stop on send.
EGRESS_ENV = "PARSECAT_ALLOW_LLM_EGRESS"
THIRD_PARTY_PROVIDER_IDS = frozenset({"anthropic", "openai", "openai-codex", "grok", "openrouter"})

PROVIDERS = [
    {"id": "anthropic", "label": "Claude (Anthropic)", "requires_env": "ANTHROPIC_API_KEY"},
    {"id": "openai", "label": "GPT (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "openai-codex", "label": "Codex (OpenAI)", "requires_env": "OPENAI_API_KEY"},
    {"id": "grok", "label": "Grok (xAI)", "requires_env": "XAI_API_KEY"},
    {"id": "openrouter", "label": "OpenRouter (multi-model gateway)", "requires_env": "OPENROUTER_API_KEY"},
    {"id": "stub", "label": "Stub (no LLM, echoes facts)", "requires_env": None},
]

# Providers a user can bring their own key for (see get_byok_client and
# app/api/routes.py's /api/account/byok/{provider} endpoints). Everything
# here except "openrouter" is a direct vendor API -- BYOK originally only
# covered OpenRouter (one key format for any model family); this is the
# generalization to a user's own direct Anthropic/OpenAI/xAI keys too.
BYOK_PROVIDER_IDS = frozenset({"anthropic", "openai", "grok", "openrouter"})


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


# Fixed id reported as `narrated_by` when a visitor-supplied (BYOK) key ran
# the narration (#84). Deliberately a constant: the response must never
# carry the key, a key prefix, the visitor's model string, or any other
# echoed request field -- only "which kind of client actually ran".
BYOK_PROVIDER_ID = "openrouter-byok"

KNOWN_PROVIDER_IDS = frozenset(p["id"] for p in PROVIDERS)


def _auto_detect_provider() -> str:
    egress = llm_egress_allowed()
    if egress and os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if egress and os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if egress and os.environ.get("XAI_API_KEY"):
        return "grok"
    if egress and os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return "stub"


def resolve_provider_id(provider: str | None) -> str | None:
    """The provider id get_llm_client(provider) would actually run, for
    reporting as `narrated_by` (#84). Returns only an id from the fixed
    PROVIDERS list -- an unknown/garbage requested id resolves to None
    (get_llm_client raises for it anyway), never to the echoed string.
    Does not check the egress gate; callers only report this after the
    client was successfully built and narrated."""
    resolved = _auto_detect_provider() if provider is None else provider
    return resolved if resolved in KNOWN_PROVIDER_IDS else None


def get_llm_client(provider: str | None = None) -> LLMClient:
    egress = llm_egress_allowed()

    if provider is None:
        provider = _auto_detect_provider()
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
    if provider == "grok":
        from app.llm.openai_client import OpenAIClient
        api_key = os.environ.get("XAI_API_KEY")
        if not api_key:
            raise RuntimeError("XAI_API_KEY is not set")
        model = os.environ.get(XAI_MODEL_ENV, DEFAULT_GROK_MODEL)
        return OpenAIClient(model=model, api_key=api_key, base_url=XAI_BASE_URL)
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


def get_byok_client(provider: str, api_key: str, model: str | None = None) -> LLMClient:
    """A user's own key for one of BYOK_PROVIDER_IDS, used for exactly one
    narration call and never persisted here (the caller -- see
    app/api/routes.py's /api/account/byok/{provider} -- decides whether to
    persist it in UserByokKey; this function just uses whatever it's
    handed).

    Originally OpenRouter-only (one key format covers any model family via
    OpenRouter's gateway); generalized to also accept a user's own direct
    Anthropic/OpenAI/xAI key once per-user ownership existed to make that
    safe -- see the correction below, still true for every provider this
    covers.

    Gated by BYOK_ENV (default off), checked here rather than only at the
    route layer, so there is exactly one place this can be skipped from.
    Raises when the gate is closed -- callers must not silently fall back
    to Stub, which would look like "your key didn't work" instead of "this
    deployment has not turned this on."

    Correction on an earlier version of this docstring, caught in review
    (PR #83) before this ever reached a public deploy: this was described
    as "a visitor's own key sending their OWN uploaded data" and framed as
    bypassing PARSECAT_ALLOW_LLM_EGRESS on that basis -- that was wrong AT
    THE TIME, because ParseCat had no auth or upload-ownership model at
    all: every capture_id was readable and diagnose/scan-able by anyone who
    could reach the API, so a visitor's key could narrate ANY capture on
    the instance, not just one they'd uploaded. That gap is why BYOK_ENV
    exists as its own gate rather than trusting this to be automatically
    fine. It's since been fixed at the data layer (see Device.owner_user_id
    / Investigation.owner_user_id and the per-user-scoped routes in
    app/api/routes.py) -- every diagnose/scan call this function's result
    ever narrates has already been confirmed to belong to the user whose
    key this is, by the time it reaches here. BYOK_ENV stays as an explicit
    operator opt-in regardless, same shape as EGRESS_ENV for the operator's
    own key (#46) -- a deployment can still choose not to let egress happen
    through this path at all.
    """
    if not byok_allowed():
        raise RuntimeError(
            f"BYOK is disabled on this deployment: set {BYOK_ENV}=1 to allow "
            f"users to supply their own keys."
        )
    if provider not in BYOK_PROVIDER_IDS:
        raise ValueError(f"BYOK is not supported for provider {provider!r}")

    if provider == "anthropic":
        from app.llm.anthropic_client import DEFAULT_MODEL, AnthropicClient
        resolved_model = (model or "").strip() or DEFAULT_MODEL
        return AnthropicClient(model=resolved_model, api_key=api_key)
    if provider == "openai":
        from app.llm.openai_client import DEFAULT_MODEL, OpenAIClient
        resolved_model = (model or "").strip() or DEFAULT_MODEL
        return OpenAIClient(model=resolved_model, api_key=api_key)
    if provider == "grok":
        from app.llm.openai_client import OpenAIClient
        resolved_model = (model or "").strip() or DEFAULT_GROK_MODEL
        return OpenAIClient(model=resolved_model, api_key=api_key, base_url=XAI_BASE_URL)
    if provider == "openrouter":
        from app.llm.openai_client import OpenAIClient
        resolved_model = (model or "").strip() or DEFAULT_OPENROUTER_MODEL
        return OpenAIClient(model=resolved_model, api_key=api_key, base_url=OPENROUTER_BASE_URL)

    raise AssertionError(f"unreachable: provider {provider!r} is in BYOK_PROVIDER_IDS but unhandled")
