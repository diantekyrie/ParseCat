"""The actual point of per-user accounts (see app/auth.py's docstring): two
coworkers sharing one deployment must not see each other's devices,
investigations, or captures, even when they pick the exact same label.

HTTP-level, one TestClient + temp DB with two real session tokens (for two
different fabricated user ids) rather than two real User rows -- these
routes only ever check the token's user id against owner_user_id columns,
never the User table itself, so a real account isn't needed to prove
isolation (test_auth.py already covers the real-account login path).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.auth import issue_session_token
from app.db import get_session
from app.main import app
from app.models.db_models import User

USER_A_ID = 101
USER_B_ID = 202


def _headers(user_id: int) -> dict[str, str]:
    token, _ = issue_session_token(user_id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    # Every route here only ever checks a token's user id against
    # owner_user_id columns (or writes a UserByokKey row keyed by it) --
    # none of them actually need a real User row to exist. Seeded anyway
    # with explicit primary keys matching each test's minted token, since
    # it costs nothing and keeps this fixture honest about what a real
    # login would look like.
    with Session(engine) as session:
        session.add(User(id=USER_A_ID, username="user-a", password_hash="unused-in-these-tests"))
        session.add(User(id=USER_B_ID, username="user-b", password_hash="unused-in-these-tests"))
        session.commit()

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


_MINIMAL_BUGREPORT_TXT = """\
------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------
09-02 01:31:53.866  1145  1145 D keystore2: debug line 0
------ 0.326s was the duration of 'SYSTEM LOG' ------
"""


def _upload(client, user_id, label, filename="logcat.txt", investigation_label=None):
    data = {"device_label": label}
    if investigation_label:
        data["investigation_label"] = investigation_label
    return client.post(
        "/api/captures",
        data=data,
        files={"file": (filename, _MINIMAL_BUGREPORT_TXT.encode(), "text/plain")},
        headers=_headers(user_id),
    )


def test_same_device_label_from_two_users_are_unrelated(client):
    upload_a = _upload(client, USER_A_ID, "pixel")
    upload_b = _upload(client, USER_B_ID, "pixel")
    assert upload_a.status_code == 200
    assert upload_b.status_code == 200
    assert upload_a.json()["capture_id"] != upload_b.json()["capture_id"]


def test_device_list_only_shows_own_devices(client):
    _upload(client, USER_A_ID, "a-only-device")
    _upload(client, USER_B_ID, "b-only-device")

    a_devices = client.get("/api/devices", headers=_headers(USER_A_ID)).json()
    b_devices = client.get("/api/devices", headers=_headers(USER_B_ID)).json()

    assert "a-only-device" in [d["label"] for d in a_devices]
    assert "b-only-device" not in [d["label"] for d in a_devices]
    assert "b-only-device" in [d["label"] for d in b_devices]
    assert "a-only-device" not in [d["label"] for d in b_devices]


def test_cannot_list_another_users_device_captures(client):
    _upload(client, USER_A_ID, "shared-label-name")
    _upload(client, USER_B_ID, "shared-label-name")

    r = client.get("/api/devices/shared-label-name/captures", headers=_headers(USER_A_ID))
    assert r.status_code == 200
    assert len(r.json()) == 1  # only A's own capture under this label, not B's


def test_cannot_read_another_users_capture_summary(client):
    upload = _upload(client, USER_A_ID, "a-device")
    capture_id = upload.json()["capture_id"]

    as_owner = client.get(f"/api/captures/{capture_id}/summary", headers=_headers(USER_A_ID))
    assert as_owner.status_code == 200

    as_other = client.get(f"/api/captures/{capture_id}/summary", headers=_headers(USER_B_ID))
    assert as_other.status_code == 404  # not 403 -- never confirms the id exists to a non-owner


def test_cannot_archive_another_users_device(client):
    _upload(client, USER_A_ID, "a-device")

    r = client.post("/api/devices/a-device/archive", headers=_headers(USER_B_ID))
    assert r.status_code == 404

    # Confirm it's untouched from A's side.
    listing = client.get("/api/devices", headers=_headers(USER_A_ID)).json()
    assert next(d for d in listing if d["label"] == "a-device")["archived"] is False


def test_cannot_read_another_users_investigation(client):
    _upload(client, USER_A_ID, "a-device", investigation_label="a-only-case")

    as_owner = client.get("/api/investigations/a-only-case/captures", headers=_headers(USER_A_ID))
    assert as_owner.status_code == 200

    as_other = client.get("/api/investigations/a-only-case/captures", headers=_headers(USER_B_ID))
    assert as_other.status_code == 404


# --- Personal BYOK settings (/api/account/byok/{provider}) -----------------

def test_byok_status_defaults_to_unconfigured_for_every_provider(client):
    r = client.get("/api/llm/byok_status", headers=_headers(USER_A_ID))
    assert r.status_code == 200
    providers = r.json()["providers"]
    assert set(providers) == {"anthropic", "openai", "grok", "openrouter"}
    assert all(p["configured"] is False for p in providers.values())


def test_set_and_clear_account_byok_key_for_one_provider(client):
    put = client.put(
        "/api/account/byok/anthropic",
        json={"api_key": "sk-ant-fake-key", "model": "claude-opus-5-5"},
        headers=_headers(USER_A_ID),
    )
    assert put.status_code == 200
    assert put.json() == {"provider": "anthropic", "configured": True, "model": "claude-opus-5-5"}

    status = client.get("/api/llm/byok_status", headers=_headers(USER_A_ID)).json()
    assert status["providers"]["anthropic"] == {"configured": True, "model": "claude-opus-5-5"}
    assert status["providers"]["openai"] == {"configured": False, "model": None}  # untouched
    assert "sk-ant-fake-key" not in str(status)  # the raw key is never echoed back

    delete = client.delete("/api/account/byok/anthropic", headers=_headers(USER_A_ID))
    assert delete.status_code == 200
    assert delete.json() == {"provider": "anthropic", "configured": False, "model": None}

    status_after = client.get("/api/llm/byok_status", headers=_headers(USER_A_ID)).json()
    assert status_after["providers"]["anthropic"]["configured"] is False


def test_set_account_byok_key_rejects_unknown_provider(client):
    r = client.put(
        "/api/account/byok/not-a-real-provider",
        json={"api_key": "whatever"},
        headers=_headers(USER_A_ID),
    )
    assert r.status_code == 404


def test_account_byok_keys_are_per_provider_for_the_same_user(client):
    client.put("/api/account/byok/anthropic", json={"api_key": "ant-key"}, headers=_headers(USER_A_ID))
    client.put("/api/account/byok/openai", json={"api_key": "oai-key"}, headers=_headers(USER_A_ID))

    status = client.get("/api/llm/byok_status", headers=_headers(USER_A_ID)).json()["providers"]
    assert status["anthropic"]["configured"] is True
    assert status["openai"]["configured"] is True
    assert status["grok"]["configured"] is False
    assert status["openrouter"]["configured"] is False


def test_account_byok_key_is_private_to_each_user(client):
    client.put("/api/account/byok/anthropic", json={"api_key": "a-secret-key"}, headers=_headers(USER_A_ID))

    status_b = client.get("/api/llm/byok_status", headers=_headers(USER_B_ID)).json()
    assert status_b["providers"]["anthropic"]["configured"] is False
