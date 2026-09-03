"""PC-narration-005/006/007: date-specific 'no evidence' vs capture coverage.

Synthetic timestamps only. No PII, no real serials. Asserts on the
deterministic capture_coverage bundle field, not LLM prose.
"""
from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import Capture, Device, FocusEventRow
from app.services.coverage import parse_question_date
from app.services.reasoning import build_diagnosis_bundle, diagnose, scan_capture


GAP_WORDING = ("gap", "outside", "hole", "out of range", "out-of-range", "not cover")


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _device(session, label="synthetic-coverage-phone"):
    device = Device(label=label)
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def _capture(session, device, filename):
    cap = Capture(device_id=device.id, original_filename=filename)
    session.add(cap)
    session.commit()
    session.refresh(cap)
    return cap


def _focus(session, capture_id, timestamp):
    session.add(FocusEventRow(
        capture_id=capture_id,
        timestamp=timestamp,
        event_type="request",
        package="com.example.maps",
        detail="synthetic focus event",
        source_section="system_log",
        source_line_start=1,
        source_line_end=1,
    ))
    session.commit()


def test_parse_question_date_known_formats_only():
    assert parse_question_date("Where was GPS on Aug 28?")["display"] == "08-28"
    assert parse_question_date("what happened on 2026-08-28")["display"] == "2026-08-28"
    assert parse_question_date("location on 08-28")["display"] == "08-28"
    assert parse_question_date("Was there a crash on this device?")["parse"] == "absent"
    assert parse_question_date("Full automatic scan: what problems are present on this device?")["parse"] == "absent"
    # Month name with no day, or an impossible day: flag, do not guess.
    assert parse_question_date("something in August")["parse"] == "unparsed"
    assert parse_question_date("GPS on Feb 30")["parse"] == "unparsed"


def test_pc_narration_005_date_outside_loaded_captures(session):
    """Date-specific question; date OUTSIDE all loaded capture ranges."""
    device = _device(session)
    cap = _capture(session, device, "synthetic-aug19.zip")
    _focus(session, cap.id, "08-19 12:00:00")

    result = diagnose(
        session, cap.id, device.label,
        "Where was GPS on Aug 28?",
    )
    coverage = result["bundle"]["capture_coverage"]
    assert coverage["question_date"] == "08-28"
    assert coverage["question_date_parse"] == "parsed"
    assert coverage["relation"] == "outside"
    assert coverage["overall_first_date"] == "08-19"
    assert coverage["overall_last_date"] == "08-19"
    stmt = coverage["statement"]
    assert stmt
    assert "08-19" in stmt
    assert "08-28" in stmt
    assert "outside" in stmt.lower()
    # Template/code statement, not a bare "no evidence".
    assert "no evidence" not in stmt.lower()
    details = [e["detail"] for e in result["bundle"]["evidence_sources"]]
    assert stmt in details


def test_pc_narration_006_date_inside_no_evidence_is_not_a_gap(session):
    """Date WITHIN range; no matching GPS rows. Must NOT imply a coverage gap."""
    device = _device(session)
    cap = _capture(session, device, "synthetic-aug19.zip")
    _focus(session, cap.id, "08-19 09:00:00")
    _focus(session, cap.id, "08-19 18:00:00")

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Where was GPS on Aug 19?",
    )
    coverage = bundle["capture_coverage"]
    assert coverage["question_date"] == "08-19"
    assert coverage["relation"] == "inside"
    assert coverage["overall_first_date"] == "08-19"
    assert coverage["overall_last_date"] == "08-19"
    assert coverage["gaps"] == []
    stmt = coverage["statement"].lower()
    for word in GAP_WORDING:
        assert word not in stmt, word
    assert "checked" in stmt
    # Location evidence was looked at; nothing GPS-shaped was found.
    assert "gnss_signal_evidence" not in bundle
    assert "location_snapshot_evidence" not in bundle


def test_pc_narration_007_gap_between_captures_not_just_minmax(session):
    """Two captures (Aug 19 and Sep 3); question date in the hole between them."""
    device = _device(session)
    cap_aug = _capture(session, device, "synthetic-aug19.zip")
    cap_sep = _capture(session, device, "synthetic-sep03.zip")
    _focus(session, cap_aug.id, "08-19 12:00:00")
    _focus(session, cap_sep.id, "09-03 12:00:00")

    bundle = build_diagnosis_bundle(
        session, cap_aug.id, device.label,
        "What happened on Aug 28?",
    )
    coverage = bundle["capture_coverage"]
    assert coverage["question_date"] == "08-28"
    assert coverage["relation"] == "in_gap"
    # Overall min/max would hide the Aug 20-Sep 2 hole.
    assert coverage["overall_first_date"] == "08-19"
    assert coverage["overall_last_date"] == "09-03"
    assert coverage["gaps"], "gap metadata must be present, not only min/max"
    gap = coverage["gaps"][0]
    assert gap["after_date"] == "08-19"
    assert gap["before_date"] == "09-03"
    assert gap["gap_first_date"] == "08-20"
    assert gap["gap_last_date"] == "09-02"
    stmt = coverage["statement"].lower()
    assert "gap" in stmt
    assert "08-28" in coverage["statement"]
    assert "08-20" in coverage["statement"]
    assert "09-02" in coverage["statement"]
    # Per-capture dates, not only the spanning min/max.
    assert "08-19" in coverage["statement"]
    assert "09-03" in coverage["statement"]


def test_no_date_in_question_does_not_fake_a_coverage_warning(session):
    device = _device(session)
    cap = _capture(session, device, "synthetic-aug19.zip")
    _focus(session, cap.id, "08-19 12:00:00")

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Was there a crash on this device?",
    )
    coverage = bundle["capture_coverage"]
    assert coverage["question_date_parse"] == "absent"
    assert coverage["question_date"] is None
    assert coverage["relation"] is None
    assert coverage["statement"] is None
    cats = [e["category"] for e in bundle["evidence_sources"]]
    assert "capture date coverage" not in cats


def test_scan_without_a_question_date_has_no_coverage_warning(session):
    device = _device(session)
    cap = _capture(session, device, "synthetic-aug19.zip")
    _focus(session, cap.id, "08-19 12:00:00")

    result = scan_capture(session, cap.id, device.label)
    coverage = result["bundle"]["capture_coverage"]
    assert coverage["question_date_parse"] == "absent"
    assert coverage["statement"] is None
    assert coverage["relation"] is None
