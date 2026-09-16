# Local LLM keys via `backend/.env` (short-term)

**Issue:** [#51](https://github.com/diantekyrie/ParseCat/issues/51) short-term slice only.

End users cannot yet enter LLM API keys in the product UI. Until Settings →
disk secrets ships (blocked on egress gate work — see PR #46), operators
configure keys with a **gitignored** `backend/.env` that uvicorn loads at
startup via `load_dotenv()` in `app.main`.

This is local disk only. Do **not** put keys in SQLite, localStorage, chat,
issues, or PRs.

## Security warnings

- **Never commit `.env`.** Root `.gitignore` already ignores `.env`.
- **Never paste API keys into chat, Slack, issues, or pull requests.**
- Keys must live on the machine that runs the backend (FastAPI is what
  calls the provider). Browser-only storage cannot feed uvicorn without
  shipping the key on every Diagnose call.
- After changing `.env`, **restart uvicorn** so `load_dotenv()` re-reads it.

## Required / optional env vars

| Variable | Required? | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | If using OpenRouter | OpenRouter multi-model gateway key |
| `ANTHROPIC_API_KEY` | If using Claude | Anthropic API key |
| `OPENAI_API_KEY` | If using GPT / Codex | OpenAI API key |
| `PARSECAT_ALLOW_LLM_EGRESS` | **Yes for live third-party send** | Opt-in gate. Set to `1` (also `true` / `yes` / `on`). Without it, Diagnose/Scan stay on Stub even when keys exist (default-deny once PR #46 is on `main`). |
| `OPENROUTER_MODEL` | Optional | OpenRouter model id (provider-prefixed), e.g. `anthropic/claude-sonnet-4.5` or `x-ai/grok-4` |
| `OPENAI_MODEL` | Optional | Override default GPT model |
| `OPENAI_CODEX_MODEL` | Optional | Override default Codex-family model |

Stub (`provider=stub`) needs no key and never leaves the machine.

> **Note:** OpenRouter + the egress gate land with PR #46. On current
> `main` without that merge, `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` still
> activate Claude/GPT; document and set `PARSECAT_ALLOW_LLM_EGRESS` /
> `OPENROUTER_*` now so a fresh clone is ready when egress merges.

## Example `backend/.env`

```bash
# Pick the provider(s) you use — omit the rest.
OPENROUTER_API_KEY=...
# ANTHROPIC_API_KEY=...
# OPENAI_API_KEY=...

# Required for live third-party Diagnose/Scan once egress gate is active:
PARSECAT_ALLOW_LLM_EGRESS=1

# Optional:
# OPENROUTER_MODEL=anthropic/claude-sonnet-4.5
```

## Helper script (optional)

From the repo:

```bash
python backend/scripts/set_llm_key.py
# or non-interactive for non-secrets:
python backend/scripts/set_llm_key.py --key PARSECAT_ALLOW_LLM_EGRESS --value 1
```

The script:

- Writes **only** `backend/.env` (refuses any other path).
- Uses a hidden prompt for API keys and **never prints the secret**.
- Sets file mode `0600` when possible.
- Updates an existing key in place or appends a new line.

## Out of scope here

- Settings UI / HTTP endpoints that write secrets (deferred until #46 is on
  `main`; see #51 acceptance for the full UI path).
- OS keychain, cloud vaults, multi-tenant per-user key stores.
