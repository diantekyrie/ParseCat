"""Synthetic ingestion tests for device-label hardware identity (issue #14).

No real bugreport zips. Serials and fingerprints in fixtures are synthetic.
"""
from __future__ import annotations

from datetime import datetime

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import Capture, DeviceInfoRow
from app.parsers.base import DeviceInfo, ParsedCapture
from app.services.persistence import (
    DeviceIdentityMismatchError,
    UNVERIFIED_DEVICE_IDENTITY_WARNING,
    persist_capture,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _capture_with_identity(**fields) -> ParsedCapture:
    parsed = ParsedCapture()
    parsed.device_info = DeviceInfo(**fields)
    return parsed


def test_mismatching_serial_or_fingerprint_is_not_persisted(session):
    # PC-ingestion-001: second upload under the same label with different
    # hardware identity must refuse silent merge.
    first = _capture_with_identity(
        serial="serial-a",
        build_fingerprint="fingerprint-a",
        manufacturer="Maker",
        model="Model-A",
    )
    persist_capture(session, "Pixel", "first.txt", first)

    second = _capture_with_identity(
        serial="serial-b",
        build_fingerprint="fingerprint-b",
        manufacturer="Maker",
        model="Model-B",
    )
    with pytest.raises(DeviceIdentityMismatchError) as excinfo:
        persist_capture(session, "Pixel", "second.txt", second)

    err = excinfo.value
    assert err.error == "device_identity_mismatch"
    assert err.mismatched_fields == ["serial", "build_fingerprint", "model"]
    detail = err.as_api_detail()
    assert detail["mismatched_fields"] == ["serial", "build_fingerprint", "model"]
    assert "serial-a" not in str(err)
    assert "serial-b" not in str(err)
    assert "fingerprint-a" not in str(err)
    assert "fingerprint-b" not in detail["message"]
    assert session.exec(select(Capture)).all() == session.exec(
        select(Capture).where(Capture.original_filename == "first.txt")
    ).all()
    assert len(session.exec(select(Capture)).all()) == 1
    assert len(session.exec(select(DeviceInfoRow)).all()) == 1


def test_matching_identity_different_dates_merges(session):
    # PC-ingestion-002: same hardware, different capture dates is a normal merge.
    first = _capture_with_identity(serial="serial-a", build_fingerprint="fingerprint-a")
    second = _capture_with_identity(serial="serial-a", build_fingerprint="fingerprint-a")
    persist_capture(
        session, "Pixel", "day-one.txt", first,
        captured_at=datetime(2026, 8, 13, 12, 0, 0),
    )
    persist_capture(
        session, "Pixel", "day-two.txt", second,
        captured_at=datetime(2026, 8, 19, 18, 30, 0),
    )

    captures = session.exec(select(Capture).order_by(Capture.id)).all()
    assert [c.original_filename for c in captures] == ["day-one.txt", "day-two.txt"]
    assert captures[0].captured_at != captures[1].captured_at
    assert UNVERIFIED_DEVICE_IDENTITY_WARNING not in second.parse_warnings
    assert "mismatch" not in "\n".join(second.parse_warnings).lower()


def test_all_null_device_info_persists_with_warning(session):
    # PC-ingestion-003: cannot compare, so warn and still persist rather than
    # dropping a partial dump.
    first = _capture_with_identity(serial="serial-a", build_fingerprint="fingerprint-a")
    persist_capture(session, "Pixel", "known.txt", first)

    unverifiable = ParsedCapture()
    unverifiable.device_info = DeviceInfo()
    capture = persist_capture(session, "Pixel", "partial.txt", unverifiable)

    assert len(session.exec(select(Capture)).all()) == 2
    assert UNVERIFIED_DEVICE_IDENTITY_WARNING in unverifiable.parse_warnings
    assert UNVERIFIED_DEVICE_IDENTITY_WARNING in capture.parse_warnings.split("\n")