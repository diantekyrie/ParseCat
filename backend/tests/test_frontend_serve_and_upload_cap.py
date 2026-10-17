"""Regression for PR #83 Arch review: SPA path containment, /api/* 404, upload 413.

API/parser-level only — no headed UI claims.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import (
    _frontend_response,
    _is_unknown_api_path,
    _safe_frontend_file,
    app,
    mount_frontend,
)
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
    assert _safe_frontend_file(dist, r"..\/.env") is None
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


def test_frontend_response_404s_on_traversal_not_spa_fallback(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>spa-index</html>", encoding="utf-8")
    (tmp_path / "secret.env").write_text("SECRET=do-not-leak\n", encoding="utf-8")

    with pytest.raises(HTTPException) as ei:
        _frontend_response("../secret.env", dist)
    assert ei.value.status_code == 404


def test_mount_frontend_temp_dist_http_asset_spa_api_and_traversal(tmp_path):
    """TestClient + temp dist/ + sibling secret via real mount_frontend path.

    Plain `/../secret` is collapsed by httpx; `/..%2fsecret` reaches the path
    param as `../secret` — the attack shape Arch called out on #83.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "assets").mkdir()
    (dist / "index.html").write_text("<html>spa-index</html>", encoding="utf-8")
    (dist / "ok.txt").write_text("asset-body", encoding="utf-8")
    secret = tmp_path / "secret.env"
    secret.write_text("SECRET=do-not-leak\n", encoding="utf-8")

    # Ground truth: naive join would have served the sibling secret.
    assert (dist / "../secret.env").is_file()

    test_app = FastAPI()
    assert mount_frontend(test_app, dist) is True

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

        for url in ("/%2e%2e/secret.env", "/..%2fsecret.env", "/%2e%2e%2fsecret.env"):
            r = c.get(url)
            assert r.status_code == 404, url
            assert "SECRET=" not in r.text, url
            assert "do-not-leak" not in r.text, url


def test_upload_exceeds_cap_returns_413_and_cleans_temp(client, monkeypatch, tmp_path):
    monkeypatch.setenv("PARSECAT_MAX_UPLOAD_BYTES", "1024")
    # Point NamedTemporaryFile at an empty dir we can assert stays clean.
    monkeypatch.setenv("TMPDIR", str(tmp_path / "upload_tmp"))
    (tmp_path / "upload_tmp").mkdir()
    tempfile.tempdir = None  # clear gettempdir() cache so TMPDIR is honored

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

    leftovers = list((tmp_path / "upload_tmp").iterdir())
    assert leftovers == [], f"partial upload temp not cleaned: {leftovers}"
