"""#95: capture delete is a real hard delete (all capture_id rows gone).

Synthetic fixtures only. No Render wipe, no lat/long policy change.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import app
from app.models.db_models import (
    Capture,
    CrashEventRow,
    Device,
    FocusEventRow,
    Investigation,
    InvestigationCaptureLink,
    KernelLogEventRow,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
    WifiEventRow,
)
from app.services.hard_delete import (
    capture_id_tables,
    hard_delete_capture,
    tables_referencing_capture,
)


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture
def client(engine):
    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _device(session, label="synthetic-hard-delete-phone"):
    device = Device(label=label)
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def _capture(session, device, filename="synthetic-a.zip"):
    cap = Capture(device_id=device.id, original_filename=filename)
    session.add(cap)
    session.commit()
    session.refresh(cap)
    return cap


def _seed_dependent_rows(session, capture_id: int):
    session.add(FocusEventRow(
        capture_id=capture_id,
        timestamp="08-19 12:00:00",
        event_type="request",
        package="com.example.app",
        detail="synthetic focus",
        source_section="system_log",
        source_line_start=1,
        source_line_end=1,
    ))
    session.add(CrashEventRow(
        capture_id=capture_id,
        timestamp="08-19 12:01:00",
        thread="main",
        package="com.example.app",
        pid=100,
        exception_class="java.lang.RuntimeException",
        message="synthetic crash line",
        root_cause_class=None,
        root_cause_message=None,
        root_cause_frame=None,
        source_section="dropbox",
        source_line_start=1,
        source_line_end=1,
    ))
    session.add(KernelLogEventRow(
        capture_id=capture_id,
        boot_relative_sec=1.0,
        priority=4,
        priority_name="warning",
        thread="kworker",
        message="synthetic kernel warn",
        is_panic_family=False,
        source_section="KERNEL LOG",
        source_line_start=1,
        source_line_end=1,
    ))
    session.add(WifiEventRow(
        capture_id=capture_id,
        timestamp="08-19 12:02:00",
        kind="disconnection",
        ssid="ssid-test",
        bssid="aa:bb:cc:dd:ee:01",
        reason_code=3,
        reason_name="Deauthenticated: station leaving",
        locally_generated=False,
        roam=None,
        source_section="wifi",
        source_line_start=1,
        source_line_end=1,
    ))
    session.add(PacketCaptureSummaryRow(
        capture_id=capture_id,
        format="pcap",
        linktype=127,
        linktype_name="IEEE802_11_RADIO",
        total_packets=1,
        captured_bytes=100,
        original_bytes=100,
        first_timestamp="1.0",
        last_timestamp="1.0",
        truncated_packets=0,
        malformed_packets=0,
    ))
    session.add(PacketAnalysisRow(
        capture_id=capture_id,
        backend="fallback",
        packets_analyzed=1,
        link_layer="802.11",
        retry_count=0,
        retry_rate_pct=0.0,
        rssi_min_dbm=-60,
        rssi_max_dbm=-60,
        rssi_avg_dbm=-60.0,
        note="synthetic",
        frame_type_breakdown_json="[]",
        identity_signals_json="[]",
        anomalies_json=json.dumps([]),
    ))
    session.commit()


def test_capture_id_tables_cover_every_metadata_table_with_fk():
    names = {t.name for t in capture_id_tables()}
    assert "capture" not in names
    assert "investigationcapturelink" in names
    assert "focuseventrow" in names
    assert "crasheventrow" in names
    assert len(names) >= 30


def test_hard_delete_removes_capture_and_all_dependent_rows(session):
    device = _device(session)
    cap = _capture(session, device)
    _seed_dependent_rows(session, cap.id)
    cid = cap.id

    assert hard_delete_capture(session, cid) is True
    assert tables_referencing_capture(session, cid) == []
    assert session.get(Capture, cid) is None
    assert session.exec(select(FocusEventRow)).all() == []
    assert session.exec(select(CrashEventRow)).all() == []
    assert session.exec(select(KernelLogEventRow)).all() == []
    assert session.exec(select(WifiEventRow)).all() == []
    assert session.exec(select(PacketCaptureSummaryRow)).all() == []
    assert session.exec(select(PacketAnalysisRow)).all() == []


def test_hard_delete_leaves_other_captures_untouched(session):
    device = _device(session)
    keep = _capture(session, device, "keep.zip")
    drop = _capture(session, device, "drop.zip")
    _seed_dependent_rows(session, keep.id)
    _seed_dependent_rows(session, drop.id)

    assert hard_delete_capture(session, drop.id) is True

    assert session.get(Capture, keep.id) is not None
    assert session.get(Capture, drop.id) is None
    assert tables_referencing_capture(session, drop.id) == []
    assert len(session.exec(select(FocusEventRow).where(FocusEventRow.capture_id == keep.id)).all()) == 1
    assert len(session.exec(select(CrashEventRow).where(CrashEventRow.capture_id == keep.id)).all()) == 1
    assert session.exec(select(FocusEventRow).where(FocusEventRow.capture_id == drop.id)).all() == []


def test_hard_delete_removes_investigation_link(session):
    device = _device(session)
    cap = _capture(session, device)
    inv = Investigation(label="synthetic-case")
    session.add(inv)
    session.commit()
    session.refresh(inv)
    session.add(InvestigationCaptureLink(investigation_id=inv.id, capture_id=cap.id))
    session.commit()

    assert hard_delete_capture(session, cap.id) is True
    assert session.exec(select(InvestigationCaptureLink)).all() == []
    # Investigation itself remains (archive/soft-hide path unchanged).
    assert session.get(Investigation, inv.id) is not None


def test_hard_delete_unknown_returns_false(session):
    assert hard_delete_capture(session, 999999) is False


def test_delete_endpoint_returns_404_afterward(client, session):
    device = _device(session)
    cap = _capture(session, device)
    _seed_dependent_rows(session, cap.id)
    cid = cap.id

    resp = client.delete(f"/api/captures/{cid}")
    assert resp.status_code == 200
    assert resp.json()["deleted_capture_id"] == cid

    assert client.get(f"/api/captures/{cid}/summary").status_code == 404
    assert client.post(
        f"/api/captures/{cid}/diagnose",
        data={"question": "why?"},
    ).status_code == 404
    assert client.delete(f"/api/captures/{cid}").status_code == 404


def test_delete_unknown_capture_is_404(client):
    assert client.delete("/api/captures/999999").status_code == 404
