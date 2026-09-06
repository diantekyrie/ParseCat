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
fail via ANTHROPIC_API_KEY/OPENAI_API_KEY leaking in; then again on this
very branch after adding the "openrouter" provider (app/llm/__init__.py) as
a THIRD auto-detection fallback -- a real OPENROUTER_API_KEY added to
backend/.env for manual testing was not covered by this fixture's original
two-key list, so the very same test failed again, this time routed to a
real OpenRouter call instead of falling through to Stub. Any future
provider added to the no-selection auto-detection chain in get_llm_client()
needs its env var added here too, or this same failure mode WILL recur a
third time.

Fix: strip all three keys from the environment before any test body
executes, session-wide, regardless of which file happens to import app.main
or in what order. Tests that want to exercise a real provider deliberately
pass provider=<id> explicitly rather than relying on ambient .env state.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True, scope="session")
def _no_real_llm_keys_in_tests():
    import os

    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        os.environ.pop(key, None)
    yield
