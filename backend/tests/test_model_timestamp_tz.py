"""Regression: Device/Capture/Investigation timestamps must be tz-aware.

SQLModel DateTime bind rejects naive datetimes (ValueError), which made
POST /api/captures 500 when creating a new device label. Defaults must
use timezone-aware UTC — never datetime.utcnow.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import Capture, Device, Investigation, InvestigationCaptureLink


def test_device_created_at_is_timezone_aware():
    d = Device(label="tz-check-device")
    assert d.created_at.tzinfo is not None
    assert d.created_at.utcoffset() == timezone.utc.utcoffset(d.created_at)


def test_capture_ingested_at_is_timezone_aware():
    c = Capture(device_id=1, original_filename="bugreport.zip")
    assert c.ingested_at.tzinfo is not None
    assert c.ingested_at.utcoffset() == timezone.utc.utcoffset(c.ingested_at)


def test_investigation_created_at_is_timezone_aware():
    inv = Investigation(label="tz-check-inv")
    assert inv.created_at.tzinfo is not None
    assert inv.created_at.utcoffset() == timezone.utc.utcoffset(inv.created_at)


def test_investigation_capture_link_added_at_is_timezone_aware():
    link = InvestigationCaptureLink(investigation_id=1, capture_id=1)
    assert link.added_at.tzinfo is not None
    assert link.added_at.utcoffset() == timezone.utc.utcoffset(link.added_at)


def test_device_and_capture_defaults_survive_session_commit():
    """Defaults must be bind-safe: SQLModel rejects naive datetimes at commit.

    Covers the original new-device upload 500 (issue #63) without a manual
    upload pass — construction-only .tzinfo checks miss the bind processor.
    """
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        device = Device(label="tz-session-device")
        session.add(device)
        session.commit()
        session.refresh(device)

        capture = Capture(device_id=device.id, original_filename="bugreport.zip")
        session.add(capture)
        session.commit()
        session.refresh(capture)

        assert device.created_at.tzinfo is not None
        assert device.created_at.utcoffset() == timezone.utc.utcoffset(device.created_at)
        assert capture.ingested_at.tzinfo is not None
        assert capture.ingested_at.utcoffset() == timezone.utc.utcoffset(capture.ingested_at)


def test_naive_captured_at_survives_session_commit():
    """Caller-supplied naive captured_at must coerce at bind, not 500.

    Defaults-only coverage misses this path (see CI failure on
    test_matching_identity_different_dates_merges before the coerce).
    """
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        device = Device(label="tz-naive-captured-at")
        session.add(device)
        session.commit()
        session.refresh(device)

        naive = datetime(2026, 8, 13, 12, 0, 0)  # intentionally naive
        assert naive.tzinfo is None
        capture = Capture(
            device_id=device.id,
            original_filename="day-one.txt",
            captured_at=naive,
        )
        session.add(capture)
        session.commit()
        session.refresh(capture)

        assert capture.captured_at is not None
        assert capture.captured_at.tzinfo is not None
        assert capture.captured_at.utcoffset() == timezone.utc.utcoffset(capture.captured_at)
        assert capture.captured_at.replace(tzinfo=None) == naive
