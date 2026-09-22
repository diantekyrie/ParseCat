"""Regression: Device/Capture/Investigation timestamps must be tz-aware.

SQLModel DateTime bind rejects naive datetimes (ValueError), which made
POST /api/captures 500 when creating a new device label. Defaults must
use timezone-aware UTC — never datetime.utcnow.
"""
from __future__ import annotations

from datetime import timezone

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


def test_investigation_capture_link_added_at_is_timezone_aware():
    link = InvestigationCaptureLink(investigation_id=1, capture_id=1)
    assert link.added_at.tzinfo is not None
