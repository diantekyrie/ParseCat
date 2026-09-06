"""Regression for issue #31 / PC-ux-003: empty .txt must not persist as a capture."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import app
from app.models.db_models import Capture
from app.services.ingestion import empty_bugreport_rejection_message, parse_bugreport_txt


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 't.db'}",
        connect_args={"check_same_thread": False},
    )
    # Import models so tables register.
    from app.models import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    with TestClient(app) as c:
        yield c, engine
    app.dependency_overrides.clear()


def test_empty_bugreport_rejection_message_for_nonsense_txt(tmp_path):
    p = tmp_path / "nonsense.txt"
    p.write_text("This is not a bugreport...\n", encoding="utf-8")
    parsed = parse_bugreport_txt(p)
    msg = empty_bugreport_rejection_message(parsed)
    assert msg is not None
    assert "No recognized bugreport section markers" in msg


def test_empty_bugreport_rejection_message_for_plain_logcat(tmp_path):
    lines = "\n".join(
        f"09-02 01:31:5{i}.866  1145  1145 D keystore2: line {i}" for i in range(10)
    )
    p = tmp_path / "logcat.txt"
    p.write_text(lines + "\n", encoding="utf-8")
    parsed = parse_bugreport_txt(p)
    msg = empty_bugreport_rejection_message(parsed)
    assert msg is not None
    assert "plain logcat capture" in msg


def test_upload_nonsense_txt_returns_422_and_does_not_persist(client):
    c, engine = client
    files = {
        "file": ("nonsense_ux.txt", b"This is not a bugreport at all.\n", "text/plain"),
    }
    data = {"device_label": "pc-ux-003-reject"}
    res = c.post("/api/captures", data=data, files=files)
    assert res.status_code == 422, res.text
    detail = res.json()["detail"]
    assert "No recognized bugreport section markers" in detail
    with Session(engine) as session:
        assert session.exec(select(Capture)).all() == []


def test_upload_plain_logcat_txt_returns_422_and_does_not_persist(client):
    c, engine = client
    body = ("\n".join(
        f"09-02 01:31:5{i}.866  1145  1145 D keystore2: line {i}" for i in range(10)
    ) + "\n").encode("utf-8")
    files = {"file": ("logcat.txt", body, "text/plain")}
    data = {"device_label": "pc-ux-003-logcat"}
    res = c.post("/api/captures", data=data, files=files)
    assert res.status_code == 422, res.text
    assert "plain logcat capture" in res.json()["detail"]
    with Session(engine) as session:
        assert session.exec(select(Capture)).all() == []
