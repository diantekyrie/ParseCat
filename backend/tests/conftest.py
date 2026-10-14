"""Session-wide test hygiene.

Importing app.main (needed for any HTTP-level test via FastAPI's TestClient)
runs `load_dotenv()` as a side effect of module import, which pulls whatever
is in backend/.env -- including a developer's real ANTHROPIC_API_KEY /
OPENAI_API_KEY / OPENROUTER_API_KEY -- into the process environment for the
rest of the pytest session. Since pytest imports every test module during
collection before running any test, that one import can silently flip EVERY
test's default LLM provider resolution from the deterministic "stub"
provider to a real, billed API call for the remainder of the run --
including tests that never touch app.main themselves and were written
expecting `[stub LLM ...]` output.

Found live TWICE now, same root cause each time: first when
test_api_user_flows.py (imports app.main) made
test_end_to_end.py::test_diagnose_returns_confidence_tied_to_corroboration
fail via ANTHROPIC_API_KEY/OPENAI_API_KEY leaking in; then again after
adding the "openrouter" provider (app/llm/__init__.py) as a THIRD
auto-detection fallback -- a real OPENROUTER_API_KEY added to backend/.env
for manual testing was not covered by this fixture's original two-key list,
so the very same test failed again, this time routed to a real OpenRouter
call instead of falling through to Stub. Any future provider added to the
no-selection auto-detection chain in get_llm_client() needs its env var
added here too, or this same failure mode WILL recur a third time.

Fix: strip all three keys from the environment before any test body
executes, session-wide, regardless of which file happens to import app.main
or in what order. Tests that want to exercise a real provider deliberately
pass provider=<id> explicitly rather than relying on ambient .env state.
"""
from __future__ import annotations

import pytest

from app.auth import issue_session_token


@pytest.fixture(autouse=True, scope="session")
def _no_real_llm_keys_in_tests():
    import os

    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "PARSECAT_ALLOW_LLM_EGRESS"):
        os.environ.pop(key, None)
    yield


# app/auth.py's SessionAuthMiddleware fails CLOSED by design when
# PARSECAT_AUTH_USERNAME / PARSECAT_AUTH_PASSWORD are unset -- correct for a
# real deploy (this branch exists specifically so a misconfigured one does
# NOT silently serve the app wide open), but it would 401/503 every
# HTTP-level test in this suite otherwise. Fixed test credentials for the
# whole session, same shape as the fixture above (deterministic test
# environment), just setting rather than stripping. test_auth.py itself
# overrides/clears these locally (monkeypatch) to exercise the gate's own
# unconfigured/wrong-credential/expired-token branches, and exercises the
# real POST /api/auth/login flow rather than this shortcut.
TEST_AUTH_USERNAME = "test-user"
TEST_AUTH_PASSWORD = "test-pass"


@pytest.fixture(autouse=True, scope="session")
def _fixed_basic_auth_credentials():
    import os

    os.environ["PARSECAT_AUTH_USERNAME"] = TEST_AUTH_USERNAME
    os.environ["PARSECAT_AUTH_PASSWORD"] = TEST_AUTH_PASSWORD
    yield


def auth_headers() -> dict[str, str]:
    """Authorization header carrying a freshly-minted, valid session token --
    pass to TestClient(app, headers=auth_headers()) wherever a test
    constructs a client directly, so it isn't 401'd by SessionAuthMiddleware.
    Mints the token directly via issue_session_token() rather than going
    through POST /api/auth/login, since these call sites only need a client
    that's already past the gate, not to exercise the login flow itself.

    Named to avoid pytest collecting this as a test itself (anything
    literally named test_* in a test file/module is fair game for pytest's
    default collection, even a plain helper with no assertions in it).
    """
    token, _ = issue_session_token()
    return {"Authorization": f"Bearer {token}"}

