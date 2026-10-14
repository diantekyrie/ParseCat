"""app/auth.py's BasicAuthMiddleware: the gate itself, not the routes behind it.

Uses TestClient(app) directly against whatever path -- these tests care only
about which status code the GATE produces (503 refused / 401 challenged /
passed-through-to-routing), not about what any particular route does. A
protected path that doesn't exist (e.g. "/no-such-route") is deliberate: once
a request clears the gate it falls through to normal FastAPI routing, which
404s for an unknown path -- a result clearly distinct from the gate's own 503
and 401, proving the request got past the gate rather than merely not being
blocked for some other reason.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.auth import AUTH_PASSWORD_ENV, AUTH_USERNAME_ENV
from app.main import app
from tests.conftest import TEST_AUTH_PASSWORD, TEST_AUTH_USERNAME, basic_auth_headers


def _client() -> TestClient:
    # No Authorization header by default -- individual tests add one via
    # `headers=` on the call itself so each case is explicit about what it's
    # sending (or deliberately not sending).
    return TestClient(app)


def test_unconfigured_credentials_refuse_protected_path(monkeypatch):
    monkeypatch.delenv(AUTH_USERNAME_ENV, raising=False)
    monkeypatch.delenv(AUTH_PASSWORD_ENV, raising=False)
    with _client() as c:
        r = c.get("/no-such-route")
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
        r = c.options("/no-such-route")
    assert r.status_code != 503
    assert r.status_code != 401


def test_configured_missing_header_is_401_with_challenge():
    with _client() as c:
        r = c.get("/no-such-route")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="ParseCat"'


def test_configured_wrong_username_is_401():
    token = base64.b64encode(f"wrong-user:{TEST_AUTH_PASSWORD}".encode()).decode()
    with _client() as c:
        r = c.get("/no-such-route", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 401


def test_configured_wrong_password_is_401():
    token = base64.b64encode(f"{TEST_AUTH_USERNAME}:wrong-pass".encode()).decode()
    with _client() as c:
        r = c.get("/no-such-route", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 401


def test_configured_malformed_header_is_401():
    with _client() as c:
        r = c.get("/no-such-route", headers={"Authorization": "not-even-basic"})
    assert r.status_code == 401


def test_configured_correct_credentials_pass_through():
    with _client() as c:
        r = c.get("/no-such-route", headers=basic_auth_headers())
    # Cleared the gate -- 404 from normal routing, not the gate's own codes.
    assert r.status_code == 404
    assert r.status_code not in (401, 503)
