"""Regression for PR #83 Arch review: SPA path containment, /api/* 404, upload 413.

API/parser-level only — no headed UI claims.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import _is_unknown_api_path, _safe_frontend_file, app
from app.models.db_models import Capture


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 't.db'}",
        connect_args={"check_same_thread": False},
    )
    from app.models import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    with TestClient(app) as c:
        yield c, engine
    app.dependency_overrides.clear()


def test_safe_frontend_file_serves_in_dist_asset(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    asset = dist / "app.js"
    asset.write_text("ok", encoding="utf-8")
    (dist / "index.html").write_text("<html></html>", encoding="utf-8")

    got = _safe_frontend_file(dist, "app.js")
    assert got == asset.resolve()


def test_safe_frontend_file_blocks_parent_traversal(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html></html>", encoding="utf-8")
    secret = tmp_path / ".env"
    secret.write_text("SECRET=do-not-leak\n", encoding="utf-8")

    # Direct join without resolve+containment would see this as a real file.
    assert (dist / "../.env").resolve() == secret.resolve()
    assert (dist / "../.env").is_file()

    assert _safe_frontend_file(dist, "../.env") is None
    assert _safe_frontend_file(dist, "..\\/.env") is None
    assert _safe_frontend_file(dist, "subdir/../../.env") is None


def test_safe_frontend_file_missing_and_empty_return_none(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html></html>", encoding="utf-8")

    assert _safe_frontend_file(dist, "missing.js") is None
    assert _safe_frontend_file(dist, "") is None


def test_is_unknown_api_path():
    assert _is_unknown_api_path("api") is True
    assert _is_unknown_api_path("api/does-not-exist-xyz") is True
    assert _is_unknown_api_path("api/") is True
    assert _is_unknown_api_path("index.html") is False
    assert _is_unknown_api_path("assets/app.js") is False
    assert _is_unknown_api_path("apples") is False


def test_spa_serve_helpers_via_temp_dist_http(tmp_path):
    """HTTP-level exercise of the same decision helpers serve_frontend uses.

    The production catch-all is only registered at import when frontend/dist
    exists, so CI without a build would flake on app.main's route. This tiny
    app mirrors serve_frontend using the extracted helpers + a temp dist.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>spa-index</html>", encoding="utf-8")
    (dist / "ok.txt").write_text("asset-body", encoding="utf-8")
    secret = tmp_path / ".env"
    secret.write_text("SECRET=do-not-leak\n", encoding="utf-8")

    test_app = FastAPI()

    @test_app.get("/{full_path:path}")
    def serve(full_path: str):
        if _is_unknown_api_path(full_path):
            raise HTTPException(status_code=404, detail="Not Found")
        dist_root = dist.resolve()
        safe = _safe_frontend_file(dist_root, full_path)
        if safe is not None:
            return FileResponse(safe)
        return FileResponse(dist_root / "index.html")

    with TestClient(test_app) as c:
        r = c.get("/ok.txt")
        assert r.status_code == 200
        assert r.text == "asset-body"

        r = c.get("/some/spa/route")
        assert r.status_code == 200
        assert "spa-index" in r.text

        r = c.get("/api/does-not-exist-xyz")
        assert r.status_code == 404
        assert r.json()["detail"] == "Not Found"
        assert "text/html" not in r.headers.get("content-type", "")

        # Path-param form of traversal (what uvicorn passes after decoding).
        # Helper must refuse; SPA fallback must not leak the secret either.
        r = c.get("/../.env", follow_redirects=False)
        # httpx may normalize URL; also call helper path via crafted request
        # if the client collapses dots — still assert body never contains secret.
        if r.status_code == 200:
            assert "SECRET=" not in r.text
            assert "do-not-leak" not in r.text


def test_upload_exceeds_cap_returns_413_and_does_not_persist(client, monkeypatch):
    monkeypatch.setenv("PARSECAT_MAX_UPLOAD_BYTES", "1024")
    c, engine = client
    body = b"x" * 2048
    res = c.post(
        "/api/captures",
        data={"device_label": "upload-cap-413"},
        files={"file": ("oversized.txt", body, "text/plain")},
    )
    assert res.status_code == 413, res.text
    detail = res.json()["detail"]
    assert "Upload exceeds" in detail
    with Session(engine) as session:
        assert session.exec(select(Capture)).all() == []


def test_real_serve_frontend_rejects_encoded_traversal(tmp_path, monkeypatch):
    """TestClient against the production catch-all with percent-encoded '..'.

    Plain `/../secret` is collapsed by httpx before the path param binds;
    `/..%2fsecret` reaches serve_frontend as `../secret` — the real attack
    shape Arch called out on #83.
    """
    from app import main as main_mod

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>spa-index</html>", encoding="utf-8")
    (dist / "ok.txt").write_text("inside", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP_SECRET_OUTSIDE_DIST\n", encoding="utf-8")
    monkeypatch.setattr(main_mod, "_FRONTEND_DIST", dist)

    # Catch-all is only registered when dist existed at import; this checkout
    # stubs frontend/dist so the route is present. Monkeypatch swaps the root.
    with TestClient(app) as c:
        r = c.get("/..%2fsecret.txt")
        assert "TOP_SECRET_OUTSIDE_DIST" not in r.text
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert "spa-index" in r.text

        r2 = c.get("/ok.txt")
        assert r2.status_code == 200
        assert r2.text == "inside"

        r3 = c.get("/api/nope-encoded-check")
        assert r3.status_code == 404
        assert r3.json()["detail"] == "Not Found"
