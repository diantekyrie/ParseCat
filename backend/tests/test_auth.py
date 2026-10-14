"""app/auth.py: SessionAuthMiddleware and POST /api/auth/login.

Uses TestClient(app) directly against "/api/no-such-route" -- a path that
matches the gate's own is_api_path() check (so it's actually subject to the
gate, unlike a bare "/no-such-route", which app/auth.py deliberately exempts
as "the static frontend" -- see SessionAuthMiddleware's dispatch) but isn't
a real registered route, so once a request clears the gate it falls through
to FastAPI's own unmatched-route 404. That 404 is what "passes through"
assertions below check for: distinct from the gate's own 401/503, proving
the request got past the gate rather than merely not being blocked for some
other reason.
"""
from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app.auth import AUTH_PASSWORD_ENV, AUTH_USERNAME_ENV, issue_session_token
from app.main import app
from tests.conftest import TEST_AUTH_PASSWORD, TEST_AUTH_USERNAME, auth_headers


def _client() -> TestClient:
    # No Authorization header by default -- individual tests add one via
    # `headers=` on the call itself so each case is explicit about what it's
    # sending (or deliberately not sending).
    return TestClient(app)


def test_unconfigured_credentials_refuse_api_path(monkeypatch):
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.get("/api/no-such-route")
    assert r.status_code == 503
    assert AUTH_USERNAME_ENV in r.json()["detail"]
    assert AUTH_PASSWORD_ENV in r.json()["detail"]


def test_unconfigured_credentials_still_exempt_health(monkeypatch):
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.get("/api/health")
    assert r.status_code == 200


def test_unconfigured_credentials_still_pass_options_through(monkeypatch):
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.options("/api/no-such-route")
    assert r.status_code != 503
    assert r.status_code != 401


def test_unconfigured_credentials_login_is_503(monkeypatch):
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.post("/api/auth/login", json={"username": "x", "password": "y"})
    assert r.status_code == 503


def test_non_api_path_is_exempt_even_unconfigured(monkeypatch):
    # The static frontend (LoginGate's own HTML/JS/CSS bundle) has to be
    # reachable before anyone has a token, or even before an operator has
    # finished configuring credentials -- otherwise the login screen itself
    # can never load. It carries no capture data; every actual data read
    # still goes through a gated /api/* call (see the tests above/below).
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.get("/some/frontend/route")
    assert r.status_code not in (401, 503)


def test_non_api_path_is_exempt_when_configured_too():
    with _client() as c:
        r = c.get("/some/frontend/route")
    assert r.status_code not in (401, 503)


def test_configured_missing_header_is_401():
    with _client() as c:
        r = c.get("/api/no-such-route")
    assert r.status_code == 401


def test_configured_malformed_header_is_401():
    with _client() as c:
        r = c.get("/api/no-such-route", headers={"Authorization": "not-even-bearer"})
    assert r.status_code == 401


def test_configured_garbage_token_is_401():
    with _client() as c:
        r = c.get("/api/no-such-route", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_configured_expired_token_is_401():
    token, _ = issue_session_token(now=time.time() - 10_000)
    with _client() as c:
        r = c.get("/api/no-such-route", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_configured_valid_token_passes_through():
    with _client() as c:
        r = c.get("/api/no-such-route", headers=auth_headers())
    assert r.status_code == 404
    assert r.status_code not in (401, 503)


def test_login_wrong_username_is_401():
    with _client() as c:
        r = c.post("/api/auth/login", json={"username": "wrong-user", "password": TEST_AUTH_PASSWORD})
    assert r.status_code == 401


def test_login_wrong_password_is_401():
    with _client() as c:
        r = c.post("/api/auth/login", json={"username": TEST_AUTH_USERNAME, "password": "wrong-pass"})
    assert r.status_code == 401


def test_login_correct_credentials_issues_usable_token():
    with _client() as c:
        login = c.post("/api/auth/login", json={"username": TEST_AUTH_USERNAME, "password": TEST_AUTH_PASSWORD})
        assert login.status_code == 200
        body = login.json()
        assert body["expires_in"] > 0
        token = body["token"]

        r = c.get("/api/no-such-route", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404  # past the gate, same as the test above
