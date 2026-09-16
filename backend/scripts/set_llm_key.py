"""Interactively write/update LLM API keys in gitignored backend/.env.

Short-term operator setup for issue #51. Keys stay on the machine that
runs uvicorn (`load_dotenv()` in app.main). This script never prints the
secret value and refuses to write anywhere that is not under backend/.

Usage (from repo root or backend/):

    python backend/scripts/set_llm_key.py
    python backend/scripts/set_llm_key.py --key OPENROUTER_API_KEY
    python backend/scripts/set_llm_key.py --key PARSECAT_ALLOW_LLM_EGRESS --value 1

See docs/llm-local-keys.md.
"""
from __future__ import annotations

import argparse
import getpass
import os
import stat
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = (BACKEND_DIR / ".env").resolve()

# Vars this helper is allowed to set. Keys are prompted via getpass;
# non-secret toggles/models may use --value or a normal prompt.
SECRET_KEYS = frozenset({
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
})
PLAIN_KEYS = frozenset({
    "PARSECAT_ALLOW_LLM_EGRESS",
    "OPENROUTER_MODEL",
    "OPENAI_MODEL",
    "OPENAI_CODEX_MODEL",
})
ALLOWED_KEYS = SECRET_KEYS | PLAIN_KEYS


def _ensure_env_under_backend(path: Path) -> Path:
    """Refuse any write target that is not backend/.env (resolved)."""
    resolved = path.resolve()
    backend = BACKEND_DIR.resolve()
    try:
        resolved.relative_to(backend)
    except ValueError as exc:
        raise SystemExit(
            f"Refusing to write {resolved}: path is not under {backend}"
        ) from exc
    if resolved.name != ".env" or resolved.parent != backend:
        raise SystemExit(
            f"Refusing to write {resolved}: only {backend / '.env'} is allowed"
        )
    return resolved


def _read_env_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    # Binary-safe-ish: treat as UTF-8 text; do not print contents.
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def _upsert_env(path: Path, key: str, value: str) -> None:
    path = _ensure_env_under_backend(path)
    lines = _read_env_lines(path)
    prefix = f"{key}="
    replaced = False
    out: list[str] = []
    for line in lines:
        raw = line.rstrip("\r\n")
        if raw.startswith(prefix) or raw.startswith(f"export {prefix}"):
            out.append(f"{key}={value}\n")
            replaced = True
        else:
            out.append(line if line.endswith("\n") else line + "\n")
    if not replaced:
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        out.append(f"{key}={value}\n")

    path.parent.mkdir(parents=True, exist_ok=True)
    # Write via temp + replace so a half-written .env is unlikely.
    tmp = path.with_name(".env.parsecat.tmp")
    try:
        tmp.write_text("".join(out), encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        tmp.replace(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _prompt_key_choice() -> str:
    choices = sorted(ALLOWED_KEYS)
    print("Which env var to set?")
    for i, name in enumerate(choices, 1):
        print(f"  {i}. {name}")
    raw = input("Enter number or name: ").strip()
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(choices):
            return choices[idx - 1]
        raise SystemExit(f"Invalid choice: {raw}")
    if raw in ALLOWED_KEYS:
        return raw
    raise SystemExit(f"Unsupported key {raw!r}. Allowed: {', '.join(choices)}")


def _prompt_value(key: str, cli_value: str | None) -> str:
    if cli_value is not None:
        return cli_value
    if key in SECRET_KEYS:
        value = getpass.getpass(f"{key} (input hidden): ")
        if not value.strip():
            raise SystemExit("Empty value; nothing written.")
        confirm = getpass.getpass(f"Confirm {key}: ")
        if value != confirm:
            raise SystemExit("Values did not match; nothing written.")
        return value.strip()
    # Non-secret: normal prompt (egress flag / model id).
    value = input(f"{key}= ").strip()
    if not value:
        raise SystemExit("Empty value; nothing written.")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write/update a gitignored backend/.env LLM setting."
    )
    parser.add_argument(
        "--key",
        choices=sorted(ALLOWED_KEYS),
        help="Env var to set (interactive menu if omitted).",
    )
    parser.add_argument(
        "--value",
        help="Value to write. For API keys prefer omitting this and using the hidden prompt.",
    )
    parser.add_argument(
        "--env-path",
        type=Path,
        default=ENV_PATH,
        help="Must resolve to backend/.env (default). Other paths are refused.",
    )
    args = parser.parse_args(argv)

    key = args.key or _prompt_key_choice()
    if key not in ALLOWED_KEYS:
        raise SystemExit(f"Unsupported key {key!r}")

    # Never accept secret values on the command line in process lists if we
    # can help it — warn and still allow for non-interactive CI-like use.
    if key in SECRET_KEYS and args.value is not None:
        print(
            "Warning: passing API keys via --value may expose them in shell history.",
            file=sys.stderr,
        )

    value = _prompt_value(key, args.value)
    path = _ensure_env_under_backend(args.env_path)
    _upsert_env(path, key, value)

    # Confirm without echoing the secret.
    if key in SECRET_KEYS:
        last4 = value[-4:] if len(value) >= 4 else "****"
        print(f"Updated {path} ({key} set, ends with …{last4}). Restart uvicorn to reload.")
    else:
        print(f"Updated {path} ({key} set). Restart uvicorn to reload.")
    print("Never commit .env. Never paste keys into chat, issues, or PRs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
