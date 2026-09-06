"""Issue #36: relative time phrases ("last week", "yesterday", ...) in a
Diagnose question, resolved against the loaded captures' OWN most recent
dated event -- never real wall-clock "now". Synthetic timestamps only.
"""
from __future__ import annotations

from datetime import date

import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import Capture, Device, FocusEventRow
from app.services.coverage import (
    CalendarDay,
    build_capture_coverage,
    parse_relative_question_range,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _device(session, label="relative-date-phone"):
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


# --- parse_relative_question_range() unit tests ---------------------------

def test_no_relative_phrase_returns_none():
    anchor = CalendarDay(9, 6, 2026)
    assert parse_relative_question_range("Was there a crash?", anchor) is None


def test_phrase_present_but_no_anchor_is_reported_as_anchorless():
    result = parse_relative_question_range("What happened last week?", None)
    assert result == {"phrase": "last week", "start": None, "end": None, "anchorless": True}


def test_yesterday_resolves_to_the_day_before_the_anchor():
    anchor = CalendarDay(9, 6, 2026)  # Sunday
    result = parse_relative_question_range("What happened yesterday?", anchor)
    assert result["start"].as_date() == date(2026, 9, 5)
    assert result["end"].as_date() == date(2026, 9, 5)


def test_last_week_resolves_to_the_full_prior_calendar_week():
    # 2026-09-06 is a Sunday (weekday()==6); the week containing it starts
    # Monday 2026-08-31. "Last week" must be the full Mon-Sun week before
    # that: 2026-08-24 through 2026-08-30.
    anchor = CalendarDay(9, 6, 2026)
    result = parse_relative_question_range("What crashed last week?", anchor)
    assert result["start"].as_date() == date(2026, 8, 24)
    assert result["end"].as_date() == date(2026, 8, 30)


def test_last_n_days_resolves_to_a_trailing_window_including_the_anchor():
    anchor = CalendarDay(9, 6, 2026)
    result = parse_relative_question_range("What happened in the last 3 days?", anchor)
    assert result["start"].as_date() == date(2026, 9, 4)
    assert result["end"].as_date() == date(2026, 9, 6)


def test_last_month_resolves_to_the_full_prior_calendar_month():
    anchor = CalendarDay(9, 6, 2026)
    result = parse_relative_question_range("What happened last month?", anchor)
    assert result["start"].as_date() == date(2026, 8, 1)
    assert result["end"].as_date() == date(2026, 8, 31)


# --- build_capture_coverage() integration tests ----------------------------

def test_relative_phrase_fully_inside_loaded_captures(session):
    device = _device(session)
    cap = _capture(session, device, "bugreport.zip")
    # Anchor (most recent event) = 2026-09-06. "Last week" = 08-24..08-30.
    # The capture's own data must span AT LEAST that whole window (starting
    # on/before 08-24) for "inside" to be correct -- data that only starts
    # mid-window (e.g. 08-27) genuinely only partially covers "last week",
    # since the capture has no recorded activity for 08-24..08-26 either.
    _focus(session, cap.id, "2026-08-20 10:00:00")  # on/before the window start
    _focus(session, cap.id, "2026-08-27 10:00:00")  # inside "last week"
    _focus(session, cap.id, "2026-09-06 09:00:00")  # sets the anchor

    coverage = build_capture_coverage(session, [cap], "What crashed last week?")
    assert coverage["question_relative_phrase"] == "last week"
    assert coverage["question_range"] == {"start": "2026-08-24", "end": "2026-08-30", "phrase": "last week"}
    assert coverage["relation"] == "inside"
    assert "last week" in coverage["statement"]
    assert "2026-08-24" in coverage["statement"] and "2026-08-30" in coverage["statement"]


def test_relative_phrase_entirely_outside_loaded_captures(session):
    device = _device(session)
    cap = _capture(session, device, "bugreport.zip")
    # Only event is the anchor itself; "yesterday" (09-05) has no data.
    _focus(session, cap.id, "2026-09-06 09:00:00")

    coverage = build_capture_coverage(session, [cap], "What happened yesterday?")
    assert coverage["question_relative_phrase"] == "yesterday"
    assert coverage["relation"] == "outside"
    assert "outside loaded" in coverage["statement"]


def test_relative_phrase_partially_overlapping_loaded_captures(session):
    device = _device(session)
    cap = _capture(session, device, "bugreport.zip")
    # Data starts mid-way through "last 3 days" (09-04..09-06): only
    # 09-05 and 09-06 have events, 09-04 does not.
    _focus(session, cap.id, "2026-09-05 08:00:00")
    _focus(session, cap.id, "2026-09-06 09:00:00")

    coverage = build_capture_coverage(session, [cap], "What happened in the last 3 days?")
    assert coverage["relation"] in ("inside", "partial")
    # Data covers 09-05..09-06 which is a subset of the requested 09-04..09-06
    # window, and there's no gap *within* the dated span itself -- the
    # window's start (09-04) precedes overall_min_d (09-05), so this must
    # be "partial", not "inside".
    assert coverage["relation"] == "partial"
    assert "only the overlapping portion" in coverage["statement"].lower()


def test_relative_phrase_with_no_dated_events_at_all(session):
    device = _device(session)
    cap = _capture(session, device, "bugreport.zip")
    # No FocusEventRow at all -- no anchor exists.

    coverage = build_capture_coverage(session, [cap], "What happened last week?")
    assert coverage["question_relative_phrase"] == "last week"
    assert coverage["relation"] == "unknown"
    assert "no timestamped" in coverage["statement"]


def test_literal_date_still_takes_priority_over_relative_phrase(session):
    # A question naming both a literal date AND a relative phrase should
    # still resolve via the literal-date path (parse_question_date), since
    # that's checked first in build_capture_coverage() -- not a new
    # ambiguity introduced by this change.
    device = _device(session)
    cap = _capture(session, device, "bugreport.zip")
    _focus(session, cap.id, "2026-08-28 10:00:00")

    coverage = build_capture_coverage(session, [cap], "What happened on 2026-08-28, sometime last week?")
    assert coverage["question_date"] == "2026-08-28"
    assert coverage["question_date_parse"] == "parsed"
    assert "question_relative_phrase" not in coverage
