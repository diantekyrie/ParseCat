"""app/auth.py: SessionAuthMiddleware and POST /api/auth/login.

Unlike test_api_user_flows.py and friends (which use conftest's
auth_headers() -- a token for a fabricated id, never a real User row, since
those tests only need to get past the gate), this file exercises the real
login flow end to end, so it needs its own DB-backed client with a genuinely
seeded user and a bcrypt-checked password.

Uses "/api/no-such-route" (not a real registered route) to test what the
GATE does (503 refused / 401 challenged / passed through to FastAPI's own
unmatched-route 404) without depending on any particular route's behavior.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.auth import issue_session_token
from app.db import get_session
from app.main import app
from app.models.db_models import User

TEST_USERNAME = "auth-test-user"
TEST_PASSWORD = "auth-test-password"


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _client_with_user() -> tuple[TestClient, int]:
    """Builds a client + its own temp DB with one real, seeded user.
    Returns (client, user_id). Not a fixture itself so each test controls
    exactly when the client (and its `with` context) is entered.
    """
    from app.auth import _hash_password

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        user = User(username=TEST_USERNAME, password_hash=_hash_password(TEST_PASSWORD))
        session.add(user)
        session.commit()
        session.refresh(user)
        user_id = user.id

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    return TestClient(app), user_id


def _no_users_client() -> TestClient:
    """A temp DB with NO users at all -- for the "nothing provisioned yet" 503 case."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    return TestClient(app)


def test_no_token_refuses_api_path(client):
    r = client.get("/api/no-such-route")
    assert r.status_code == 401


def test_health_exempt_with_no_token(client):
    r = client.get("/api/health")
    assert r.status_code == 200


def test_options_exempt_with_no_token(client):
    r = client.options("/api/no-such-route")
    assert r.status_code not in (401, 503)


def test_non_api_path_exempt_with_no_token(client):
    # The static frontend (LoginGate's own HTML/JS/CSS) has to be reachable
    # before anyone has a token -- see SessionAuthMiddleware's dispatch.
    r = client.get("/some/frontend/route")
    assert r.status_code not in (401, 503)


def test_garbage_token_is_401(client):
    r = client.get("/api/no-such-route", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_malformed_header_is_401(client):
    r = client.get("/api/no-such-route", headers={"Authorization": "not-even-bearer"})
    assert r.status_code == 401


def test_expired_token_is_401(client):
    token, _ = issue_session_token(user_id=1, now=time.time() - 10_000)
    r = client.get("/api/no-such-route", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_valid_token_passes_through(client):
    token, expires_in = issue_session_token(user_id=1)
    assert expires_in > 0
    r = client.get("/api/no-such-route", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404  # past the gate -- FastAPI's own unmatched-route 404


def test_login_with_no_users_provisioned_is_503():
    c = _no_users_client()
    with c:
        r = c.post("/api/auth/login", json={"username": "anyone", "password": "anything"})
    assert r.status_code == 503
    assert "PARSECAT_BOOTSTRAP_USERS" in r.json()["detail"]
    app.dependency_overrides.clear()


def test_login_wrong_username_is_401():
    c, _ = _client_with_user()
    with c:
        r = c.post("/api/auth/login", json={"username": "nobody-by-this-name", "password": TEST_PASSWORD})
    assert r.status_code == 401
    app.dependency_overrides.clear()


def test_login_wrong_password_is_401():
    c, _ = _client_with_user()
    with c:
        r = c.post("/api/auth/login", json={"username": TEST_USERNAME, "password": "wrong-password"})
    assert r.status_code == 401
    app.dependency_overrides.clear()


def test_login_correct_credentials_issues_usable_token():
    c, user_id = _client_with_user()
    with c:
        login = c.post("/api/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
        assert login.status_code == 200
        body = login.json()
        assert body["expires_in"] > 0
        token = body["token"]

        r = c.get("/api/no-such-route", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404  # past the gate, same as test_valid_token_passes_through
    app.dependency_overrides.clear()
