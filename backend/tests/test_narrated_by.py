"""#84: report the provider that ACTUALLY narrated, separately from the
echoed request `provider`.

With BYOK on, a visitor key overrides the provider dropdown (see
reasoning._run_llm), but the response used to echo only the requested
`provider` (e.g. "stub"), so the UI labelled live OpenRouter text
"narrated by Stub". `provider` stays the echoed request value (contract in
test_api_user_flows.py::test_diagnose_unknown_provider_...); the new
`narrated_by` field carries only a fixed provider id -- never the key, a
key prefix, the visitor's model string, or an echoed request field.

HTTP-level via TestClient, synthetic in-memory captures only, and the BYOK
client is faked: no network calls, no real keys.
"""
from __future__ import annotations

import pytest

from app.llm import BYOK_ENV, BYOK_PROVIDER_ID, EGRESS_ENV, resolve_provider_id
from app.services import reasoning

# Reuse the HTTP client fixture + synthetic upload helper.
from tests.test_api_user_flows import _upload_txt, client  # noqa: F401

DUMMY_KEY = "dummy-byok-key-84-must-never-echo-0123456789"
DUMMY_MODEL = "visitor/custom-model-84-must-never-echo"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(EGRESS_ENV, raising=False)
    monkeypatch.delenv(BYOK_ENV, raising=False)
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(k, raising=False)


class _FakeByokClient:
    def narrate(self, system_prompt, user_prompt):
        return "## Summary\nlive BYOK narration (fake)"


@pytest.fixture
def fake_byok(monkeypatch):
    monkeypatch.setenv(BYOK_ENV, "1")
    calls = []

    def _fake_get_byok_client(api_key, model=None):
        calls.append((api_key, model))
        return _FakeByokClient()

    monkeypatch.setattr(reasoning, "get_byok_client", _fake_get_byok_client)
    return calls


def _assert_no_key_leak(resp):
    raw = resp.text
    assert DUMMY_KEY not in raw
    assert DUMMY_KEY[:12] not in raw  # no key prefix either
    assert DUMMY_MODEL not in raw


def test_scan_with_byok_reports_byok_id_not_the_requested_stub(client, fake_byok):
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    resp = client.post(
        f"/api/captures/{capture_id}/scan",
        data={"provider": "stub", "byok_api_key": DUMMY_KEY, "byok_model": DUMMY_MODEL},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["report"].endswith("live BYOK narration (fake)")
    assert body["narrated_by"] == "openrouter-byok" == BYOK_PROVIDER_ID
    assert body["provider"] == "stub"  # requested value still echoed
    assert fake_byok == [(DUMMY_KEY, DUMMY_MODEL)]
    _assert_no_key_leak(resp)


def test_diagnose_with_byok_reports_byok_id_not_the_requested_stub(client, fake_byok):
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    resp = client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "did it crash?", "provider": "stub",
              "byok_api_key": DUMMY_KEY, "byok_model": DUMMY_MODEL},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["narrated_by"] == "openrouter-byok"
    assert body["provider"] == "stub"
    assert body["llm_error"] is None
    _assert_no_key_leak(resp)


def test_investigation_diagnose_with_byok_reports_byok_id(client, fake_byok):
    _upload_txt(client, "Pixel", investigation_label="inv-84")
    resp = client.post(
        "/api/investigations/inv-84/diagnose",
        data={"question": "did it crash?", "provider": "stub",
              "byok_api_key": DUMMY_KEY, "byok_model": DUMMY_MODEL},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["narrated_by"] == "openrouter-byok"
    assert body["provider"] == "stub"
    _assert_no_key_leak(resp)


def test_no_key_no_provider_resolves_to_stub(client):
    # provider=None -> backend auto-picks; with no egress/keys that is stub.
    # Previously the response said provider=null and the UI showed no label.
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    for path, data in (
        (f"/api/captures/{capture_id}/scan", {}),
        (f"/api/captures/{capture_id}/diagnose", {"question": "did it crash?"}),
    ):
        resp = client.post(path, data=data)
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] is None
        assert body["narrated_by"] == "stub"


def test_explicit_stub_without_key_reports_stub(client):
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    body = client.post(f"/api/captures/{capture_id}/scan", data={"provider": "stub"}).json()
    assert body["narrated_by"] == "stub"


def test_byok_with_gate_closed_reports_no_narrator(client):
    # BYOK default-off: key supplied, gate closed -> narration fails, so
    # nothing narrated and no source label (never "Stub", never the key).
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    resp = client.post(
        f"/api/captures/{capture_id}/scan",
        data={"provider": "stub", "byok_api_key": DUMMY_KEY},
    )
    body = resp.json()
    assert body["report"] is None
    assert "BYOK is disabled" in body["llm_error"]
    assert body["narrated_by"] is None
    _assert_no_key_leak(resp)


def test_unknown_provider_never_echoed_into_narrated_by(client):
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    body = client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "q", "provider": "not-a-real-provider"},
    ).json()
    assert body["provider"] == "not-a-real-provider"  # existing echo contract
    assert body["narrated_by"] is None


def test_egress_gated_provider_reports_no_narrator(client):
    # Operator egress gate closed: requesting anthropic fails, no label.
    capture_id = _upload_txt(client, "Pixel").json()["capture_id"]
    body = client.post(
        f"/api/captures/{capture_id}/scan", data={"provider": "anthropic"},
    ).json()
    assert body["report"] is None
    assert body["narrated_by"] is None


@pytest.mark.parametrize(
    "requested, env, expected",
    [
        (None, {}, "stub"),
        (None, {EGRESS_ENV: "1", "OPENROUTER_API_KEY": "x"}, "openrouter"),
        (None, {EGRESS_ENV: "1", "ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "y"}, "anthropic"),
        (None, {"ANTHROPIC_API_KEY": "x"}, "stub"),  # key without egress -> stub
        ("openai-codex", {}, "openai-codex"),
        ("not-a-real-provider", {}, None),
        ("dummy-key-looking-string", {}, None),
    ],
)
def test_resolve_provider_id_is_a_fixed_known_id_or_none(monkeypatch, requested, env, expected):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert resolve_provider_id(requested) == expected
