"""A bad BYOK key must never be echoed back in `llm_error`.

Requested by Founders Engineer (security review of #85, refs #84): `_run_llm`
used to return `str(exc)` verbatim as `llm_error`, and that string goes
straight to the UI. A provider 401 can embed the key itself, its prefix, or a
masked fragment (e.g. ``sk-or-...abcd``) in the exception text. These tests
drive the real HTTP routes with BYOK on and a fake client whose call raises
exactly that, then assert none of it survives into the response JSON, while a
useful status class (the HTTP status) still does.

The key below is an obviously fake dummy -- no real key is used anywhere.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.db import get_session
from app.llm import BYOK_ENV, EGRESS_ENV
from app.main import app
from app.services import reasoning
from tests.conftest import auth_headers

DUMMY_KEY = "sk-or-v1-0000dummy0000test0000fake0000notreal0000abcd"
DUMMY_PREFIX = DUMMY_KEY[:8]
DUMMY_MASKED = "sk-or-...abcd"
FORBIDDEN = (DUMMY_KEY, DUMMY_PREFIX, DUMMY_MASKED)

_MINIMAL_BUGREPORT_TXT = """\
------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------
09-02 01:31:53.866  1145  1145 D keystore2: debug line 0
09-02 01:31:54.866  1145  1145 D keystore2: debug line 1
------ 0.326s was the duration of 'SYSTEM LOG' ------
"""


class _FakeProviderAuthError(Exception):
    """Shaped like the openai SDK's AuthenticationError text for a 401."""


class _KeyEchoingClient:
    def narrate(self, system_prompt, user_prompt):  # noqa: ARG002
        raise _FakeProviderAuthError(
            "Error code: 401 - {'error': {'message': 'Incorrect API key "
            f"provided: {DUMMY_KEY}. Key starting {DUMMY_PREFIX} is invalid "
            f"(masked: {DUMMY_MASKED})', 'code': 401}}}}"
        )


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    monkeypatch.setenv(BYOK_ENV, "1")
    monkeypatch.setattr(reasoning, "get_byok_client", lambda provider, key, model=None: _KeyEchoingClient())

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app, headers=auth_headers()) as c:
        yield c
    app.dependency_overrides.clear()


def _upload(client) -> int:
    resp = client.post(
        "/api/captures",
        data={"device_label": "byok-redaction-device"},
        files={"file": ("logcat.txt", _MINIMAL_BUGREPORT_TXT.encode(), "text/plain")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["capture_id"]


def _assert_no_key_material(body: dict):
    llm_error = body["llm_error"]
    assert llm_error, "narration should have failed and reported an error"
    whole = json.dumps(body)
    for needle in FORBIDDEN:
        assert needle not in llm_error, f"llm_error echoed key material: {needle!r}"
        assert needle not in whole, f"response JSON echoed key material: {needle!r}"
    # Still useful to the visitor: the status class survives redaction.
    assert "401" in llm_error


def test_diagnose_llm_error_does_not_echo_byok_key(client):
    # _resolve_byok only applies byok_api_key when `provider` is itself
    # BYOK-capable (app.llm.BYOK_PROVIDER_IDS) -- see routes.py.
    capture_id = _upload(client)
    resp = client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "why did it crash?", "provider": "openrouter", "byok_api_key": DUMMY_KEY},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["report"] is None
    _assert_no_key_material(resp.json())


def test_scan_llm_error_does_not_echo_byok_key(client):
    capture_id = _upload(client)
    resp = client.post(
        f"/api/captures/{capture_id}/scan",
        data={"provider": "openrouter", "byok_api_key": DUMMY_KEY},
    )
    assert resp.status_code == 200, resp.text
    _assert_no_key_material(resp.json())


def test_run_llm_redacts_key_and_key_like_tokens_directly(monkeypatch):
    # Unit-level, independent of routes: covers the key itself AND
    # key-like tokens that aren't the exact supplied key.
    class _Raiser:
        def narrate(self, *_):
            raise RuntimeError(
                f"Error code: 401 - bad key {DUMMY_KEY}; also saw sk-ant-api03-XYZxyz123456 "
                f"and {DUMMY_MASKED}"
            )

    monkeypatch.setattr(reasoning, "get_byok_client", lambda provider, key, model=None: _Raiser())
    report, llm_error, narrated_by = reasoning._run_llm(
        {"question": "t"}, "sys", provider=None, byok_api_key=DUMMY_KEY,
    )
    assert report is None
    assert narrated_by is None  # nothing was narrated -- the call raised
    for needle in (*FORBIDDEN, "sk-ant-api03-XYZxyz123456"):
        assert needle not in llm_error
    assert "401" in llm_error


@pytest.mark.parametrize("key", [None, DUMMY_KEY])
def test_benign_error_text_survives_unchanged(key):
    benign = "Error code: 429 rate limited"
    assert reasoning._redact_llm_error(benign, key) == benign


def test_truncated_key_echo_leaks_no_chars_past_prefix():
    # Arch #86 review 5493738353: prefix swap ran first and left chars 9..30.
    from app.services.reasoning import _redact_llm_error

    truncated = DUMMY_KEY[:20] + "..."
    out = _redact_llm_error(f"Error code: 401 - invalid key {truncated}", DUMMY_KEY)
    assert "Error code: 401" in out
    assert DUMMY_KEY[8:20] not in out
    assert DUMMY_KEY[:8] not in out
    assert "[redacted]-" not in out


@pytest.mark.parametrize("echo", [
    "AIzaSyFAKE...wxyz",
    "AIzaSyFAKE\u2026wxyz",
    "AIzaSyFAKEtrunc...",
    "AIzaSyFAKE",
    "gsk_FAKE1234...wxyz",
    "xai-FAKE1234...wxyz",
    "pplx-FAKE1234...wxyz",
    "pplx-FAKE1234567890abcdef",
    "hf_FAKE1234...wxyz",
    "hf_FAKE1234567890abcdefgh",
])
def test_masked_and_truncated_non_sk_keys_are_redacted(echo):
    out = reasoning._redact_llm_error(f"Error code: 401 - invalid key {echo} rejected", None)
    assert "Error code: 401" in out
    assert "FAKE" not in out
    assert "wxyz" not in out
    assert out.endswith("rejected")


@pytest.mark.parametrize("benign", [
    "Error code: 401 from openai (request id req_7f3a9c)",
    "model gemini-1.5-flash not found",
    "Google API returned 403 for model gemini-pro",
    "trace id 3fa85f6457174562 not found",
    "see xai docs and hf hub; gsk is a prefix",
    "model xai-grok-2 not found",
    "hf_hub download failed",
    "unknown prefix AIza and pplx- and gsk_",
])
def test_non_key_error_text_not_over_redacted(benign):
    assert reasoning._redact_llm_error(benign, None) == benign


def test_single_dot_mask_leaves_only_last_four():
    # Known, accepted gap (see comment above _KEY_LIKE_RE): the prefix part
    # is redacted, only the last-4 tail survives.
    out = reasoning._redact_llm_error("bad key AIzaSyFAKE.wxyz", None)
    assert "FAKE" not in out
    assert out == "bad key [redacted].wxyz"
