"""Read-only MCP server: tools, RO DB, soft-hide, identifier strip, caps.

Synthetic fixtures only — no real captures / PII.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import (
    Capture,
    Device,
    WifiEventRow,
)
from app.services import mcp_readonly as ro
from app.services.mcp_readonly import (
    DEFAULT_FACT_LIMIT,
    MAX_FACT_LIMIT,
    MCP_REDACT_KEYS,
    CaptureNotFoundError,
    FactNotFoundError,
    assert_engine_is_readonly,
    get_fact,
    get_verified_facts,
    list_captures,
    open_readonly_engine,
)


FAKE_SSID = "ssid-mcp-test"
FAKE_BSSID = "aa:bb:cc:dd:ee:11"
FAKE_MAC = "aa:bb:cc:dd:ee:22"


@pytest.fixture
def writable_db(tmp_path: Path):
    """Create a normal (writable) SQLite DB with synthetic rows, return path."""
    db_path = tmp_path / "parsecat.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        active = Device(label="synthetic-mcp-phone", archived=False)
        archived = Device(label="synthetic-mcp-archived", archived=True)
        session.add(active)
        session.add(archived)
        session.commit()
        session.refresh(active)
        session.refresh(archived)

        cap = Capture(device_id=active.id, original_filename="synthetic-mcp.zip")
        hidden = Capture(device_id=archived.id, original_filename="synthetic-hidden.zip")
        session.add(cap)
        session.add(hidden)
        session.commit()
        session.refresh(cap)
        session.refresh(hidden)

        session.add(WifiEventRow(
            capture_id=cap.id,
            timestamp="08-19 12:00:00.000",
            kind="disconnection",
            ssid=FAKE_SSID,
            bssid=FAKE_BSSID,
            reason_code=3,
            reason_name="Deauthenticated because sending STA is leaving",
            locally_generated=False,
            roam=None,
            source_section="wifi",
            source_line_start=10,
            source_line_end=10,
        ))
        session.commit()
        capture_id = cap.id
        hidden_id = hidden.id
    engine.dispose()
    return db_path, capture_id, hidden_id


@pytest.fixture
def ro_session(writable_db):
    db_path, capture_id, hidden_id = writable_db
    engine = open_readonly_engine(db_path)
    with Session(engine) as session:
        yield session, capture_id, hidden_id, db_path, engine


def test_mcp_redact_keys_cover_network_and_serial():
    assert "ssid" in MCP_REDACT_KEYS
    assert "bssid" in MCP_REDACT_KEYS
    assert "mac_address" in MCP_REDACT_KEYS
    assert "serial" in MCP_REDACT_KEYS


def test_open_readonly_engine_rejects_writes(writable_db):
    db_path, _, _ = writable_db
    engine = open_readonly_engine(db_path)
    assert_engine_is_readonly(engine)
    with engine.connect() as conn:
        with pytest.raises(OperationalError):
            conn.exec_driver_sql("CREATE TABLE should_fail (id INTEGER)")
            conn.commit()


def test_list_captures_hides_archived_device(ro_session):
    session, capture_id, hidden_id, _, _ = ro_session
    rows = list_captures(session)
    ids = {r["id"] for r in rows}
    assert capture_id in ids
    assert hidden_id not in ids
    row = next(r for r in rows if r["id"] == capture_id)
    assert row["label"] == "synthetic-mcp-phone"
    assert row["kind"] == "bugreport"
    assert "counts" in row
    assert "serial" not in row
    assert "ssid" not in json.dumps(row)


def test_get_verified_facts_strips_identifiers(ro_session):
    session, capture_id, _, _, _ = ro_session
    payload = get_verified_facts(session, capture_id)
    assert payload["capture_id"] == capture_id
    assert payload["total"] >= 1
    blob = json.dumps(payload, default=str).lower()
    assert FAKE_SSID.lower() not in blob
    assert FAKE_BSSID.lower() not in blob
    assert FAKE_MAC.lower() not in blob
    for fact in payload["facts"]:
        for key in ("ssid", "bssid", "mac_address", "serial"):
            assert key not in fact
    wifi = [f for f in payload["facts"] if f.get("category") == "wifi"]
    assert wifi, "expected wifi verified_fact from synthetic disconnection"
    assert any("disconnection" in (f.get("summary") or "").lower() for f in wifi)


def test_get_verified_facts_unknown_capture(ro_session):
    session, _, _, _, _ = ro_session
    with pytest.raises(CaptureNotFoundError):
        get_verified_facts(session, 999999)


def test_get_verified_facts_hides_archived_capture(ro_session):
    session, _, hidden_id, _, _ = ro_session
    with pytest.raises(CaptureNotFoundError):
        get_verified_facts(session, hidden_id)


def test_get_verified_facts_enforces_limit_cap(ro_session):
    session, capture_id, _, _, _ = ro_session
    payload = get_verified_facts(session, capture_id, limit=1)
    assert payload["limit"] == 1
    assert payload["returned"] <= 1
    over = get_verified_facts(session, capture_id, limit=MAX_FACT_LIMIT + 1000)
    assert over["limit"] == MAX_FACT_LIMIT


def test_get_fact_by_id(ro_session):
    session, capture_id, _, _, _ = ro_session
    payload = get_verified_facts(session, capture_id)
    assert payload["facts"], "need at least one fact"
    fact_id = payload["facts"][0]["fact_id"]
    assert fact_id.startswith("vf_")
    found = get_fact(session, fact_id, capture_id=capture_id)
    assert found["fact_id"] == fact_id
    with pytest.raises(FactNotFoundError):
        get_fact(session, "vf_deadbeefdeadbeef", capture_id=capture_id)


def test_mcp_server_tool_list_has_no_write_tools():
    from app.mcp_server import READONLY_TOOL_NAMES, WRITEISH_TOOL_NAME_FRAGMENTS, mcp

    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert names == set(READONLY_TOOL_NAMES)
    for name in names:
        lowered = name.lower()
        for frag in WRITEISH_TOOL_NAME_FRAGMENTS:
            assert frag not in lowered, f"tool {name!r} looks write-capable"


def test_default_fact_limit_constant():
    assert DEFAULT_FACT_LIMIT == 100
    assert MAX_FACT_LIMIT == 500
