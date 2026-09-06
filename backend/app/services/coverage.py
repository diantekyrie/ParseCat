"""Deterministic capture-date coverage for diagnose/scan bundles.

A date-specific "no evidence" answer is misleading when the loaded captures
never covered that date. This module computes per-capture calendar spans
from already-persisted timestamps, then classifies a question date as
inside, outside, or in a gap between captures. Narration may display these
fields; it must not invent them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlmodel import Session, select

from app.models.db_models import (
    AnrRow,
    BtHciEventRow,
    BtHciSummaryRow,
    Capture,
    CdmPairingEventRow,
    CrashEventRow,
    FocusEventRow,
    GnssSignalIntervalRow,
    PacketCaptureSummaryRow,
    ProcessKillEventRow,
    ProcessMemorySampleRow,
    SelinuxDenialRow,
    TombstoneRow,
    WifiEventRow,
)

# Dated shapes already used by frontend/src/incidentWindow.js and
# summary._LOGCAT_TS_RE. Time is optional: coverage is calendar-day grain.
_ISO_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_MD_DATE_RE = re.compile(r"\b(\d{2})-(\d{2})(?:[ T]\d{1,2}:\d{2})?")

# Month names appear in the issue's own examples ("Aug 28"). Anything
# wilder than ISO / MM-DD / English month+day is flagged unparsed rather
# than guessed.
_MONTHS = {
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sept": 9, "sep": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}
_MONTH_ALT = "|".join(sorted(_MONTHS, key=len, reverse=True))
_MONTH_TOKEN_RE = re.compile(rf"\b(?:{_MONTH_ALT})\b", re.IGNORECASE)
_MONTH_DAY_RE = re.compile(
    rf"\b(?P<month>{_MONTH_ALT})\.?\s+(?P<day>\d{{1,2}})(?:st|nd|rd|th)?"
    rf"(?:,?\s+(?P<year>\d{{4}}))?",
    re.IGNORECASE,
)
_DAY_MONTH_RE = re.compile(
    rf"\b(?P<day>\d{{1,2}})(?:st|nd|rd|th)?\s+(?P<month>{_MONTH_ALT})\.?"
    rf"(?:,?\s+(?P<year>\d{{4}}))?",
    re.IGNORECASE,
)

# Dummy year for yearless logcat ordinals -- same known limit as the
# incident-window helper (dated ordinals do not year-wrap).
_ARITHMETIC_YEAR = 2026

# Relative time phrases (issue #36). Resolved against the loaded captures'
# OWN most recent dated event -- never real wall-clock "now" -- matching
# this system's core rule that a date claim must be grounded in the
# capture's own data, not the outside world. A bugreport pulled months ago
# has "last week" mean the week before that phone's own last activity.
_RELATIVE_LAST_N_DAYS_RE = re.compile(r"\b(?:last|past)\s+(\d+)\s+days?\b", re.IGNORECASE)
_RELATIVE_YESTERDAY_RE = re.compile(r"\byesterday\b", re.IGNORECASE)
_RELATIVE_TODAY_RE = re.compile(r"\btoday\b", re.IGNORECASE)
_RELATIVE_LAST_WEEK_RE = re.compile(r"\b(?:last|previous)\s+week\b", re.IGNORECASE)
_RELATIVE_THIS_WEEK_RE = re.compile(r"\bthis\s+week\b", re.IGNORECASE)
_RELATIVE_LAST_MONTH_RE = re.compile(r"\b(?:last|previous)\s+month\b", re.IGNORECASE)
_RELATIVE_THIS_MONTH_RE = re.compile(r"\bthis\s+month\b", re.IGNORECASE)


@dataclass(frozen=True)
class CalendarDay:
    month: int
    day: int
    year: int | None = None

    def display(self) -> str:
        if self.year is not None:
            return f"{self.year:04d}-{self.month:02d}-{self.day:02d}"
        return f"{self.month:02d}-{self.day:02d}"

    def as_date(self) -> date:
        return date(
            self.year if self.year is not None else _ARITHMETIC_YEAR,
            self.month,
            self.day,
        )


def _valid_day(year: int | None, month: int, day: int) -> bool:
    try:
        date(year if year is not None else _ARITHMETIC_YEAR, month, day)
        return True
    except ValueError:
        return False


def parse_timestamp_day(ts) -> CalendarDay | None:
    """Calendar day of a stored capture/event timestamp. None if unparseable."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return CalendarDay(ts.month, ts.day, ts.year)
    if isinstance(ts, date):
        return CalendarDay(ts.month, ts.day, ts.year)
    s = str(ts).strip()
    if not s:
        return None
    m = _ISO_DATE_RE.search(s)
    if m:
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if _valid_day(year, month, day):
            return CalendarDay(month, day, year)
        return None
    m = _MD_DATE_RE.search(s)
    if m:
        month, day = int(m.group(1)), int(m.group(2))
        if _valid_day(None, month, day):
            return CalendarDay(month, day, None)
    return None


def parse_question_date(question: str) -> dict:
    """Parse a calendar date from a user question without guessing wild formats.

    Returns parse='absent'|'parsed'|'unparsed', plus day/display when parsed.
    """
    if not question or not str(question).strip():
        return {"parse": "absent", "day": None, "display": None}

    iso = _ISO_DATE_RE.search(question)
    if iso:
        year, month, day = int(iso.group(1)), int(iso.group(2)), int(iso.group(3))
        if _valid_day(year, month, day):
            parsed = CalendarDay(month, day, year)
            return {"parse": "parsed", "day": parsed, "display": parsed.display()}
        return {"parse": "unparsed", "day": None, "display": None}

    mdn = _MONTH_DAY_RE.search(question) or _DAY_MONTH_RE.search(question)
    if mdn:
        month = _MONTHS[mdn.group("month").lower().rstrip(".")]
        day = int(mdn.group("day"))
        year_s = mdn.group("year")
        year = int(year_s) if year_s else None
        if _valid_day(year, month, day):
            parsed = CalendarDay(month, day, year)
            return {"parse": "parsed", "day": parsed, "display": parsed.display()}
        return {"parse": "unparsed", "day": None, "display": None}

    if _MONTH_TOKEN_RE.search(question):
        # Month name with no parseable day -- don't guess "August" into a date.
        return {"parse": "unparsed", "day": None, "display": None}

    md = _MD_DATE_RE.search(question)
    if md:
        month, day = int(md.group(1)), int(md.group(2))
        if _valid_day(None, month, day):
            parsed = CalendarDay(month, day, None)
            return {"parse": "parsed", "day": parsed, "display": parsed.display()}
        return {"parse": "unparsed", "day": None, "display": None}

    return {"parse": "absent", "day": None, "display": None}


_RELATIVE_PHRASES: tuple[tuple[re.Pattern, str], ...] = (
    (_RELATIVE_LAST_N_DAYS_RE, "last N days"),
    (_RELATIVE_YESTERDAY_RE, "yesterday"),
    (_RELATIVE_TODAY_RE, "today"),
    (_RELATIVE_LAST_WEEK_RE, "last week"),
    (_RELATIVE_THIS_WEEK_RE, "this week"),
    (_RELATIVE_LAST_MONTH_RE, "last month"),
    (_RELATIVE_THIS_MONTH_RE, "this month"),
)


def parse_relative_question_range(question: str, anchor: CalendarDay | None) -> dict | None:
    """Resolve a relative time phrase ("last week", "yesterday", "last N
    days", ...) into a concrete [start, end] CalendarDay range, anchored to
    `anchor` -- the loaded captures' own most recent dated event. See the
    module-level comment by the regexes above for why the anchor is never
    real wall-clock "now".

    Returns None if no relative phrase is found in the question at all.
    If a phrase IS found but there's no anchor to resolve it against (no
    dated capture data whatsoever), returns {"phrase": ..., "start": None,
    "end": None, "anchorless": True} so the caller can still name which
    phrase was seen instead of silently doing nothing (parse_question_date
    doesn't need this distinction since a literal date needs no anchor).
    """
    if not question or not str(question).strip():
        return None

    n_days_match = _RELATIVE_LAST_N_DAYS_RE.search(question)
    matched_phrase = None
    if n_days_match:
        matched_phrase = f"last {n_days_match.group(1)} days"
    else:
        for rx, phrase in _RELATIVE_PHRASES[1:]:  # skip last-N-days, handled above
            if rx.search(question):
                matched_phrase = phrase
                break
    if matched_phrase is None:
        return None

    if anchor is None:
        return {"phrase": matched_phrase, "start": None, "end": None, "anchorless": True}

    anchor_d = anchor.as_date()
    yearless = anchor.year is None

    def _day(d: date) -> CalendarDay:
        return CalendarDay(d.month, d.day, None if yearless else d.year)

    if n_days_match:
        n = int(n_days_match.group(1))
        start = anchor_d - timedelta(days=n - 1)
        return {"phrase": matched_phrase, "start": _day(start), "end": _day(anchor_d), "anchorless": False}

    if _RELATIVE_YESTERDAY_RE.search(question):
        d = anchor_d - timedelta(days=1)
        return {"phrase": matched_phrase, "start": _day(d), "end": _day(d), "anchorless": False}

    if _RELATIVE_TODAY_RE.search(question):
        return {"phrase": matched_phrase, "start": _day(anchor_d), "end": _day(anchor_d), "anchorless": False}

    if _RELATIVE_LAST_WEEK_RE.search(question):
        this_week_start = anchor_d - timedelta(days=anchor_d.weekday())
        last_week_start = this_week_start - timedelta(days=7)
        last_week_end = this_week_start - timedelta(days=1)
        return {"phrase": matched_phrase, "start": _day(last_week_start), "end": _day(last_week_end), "anchorless": False}

    if _RELATIVE_THIS_WEEK_RE.search(question):
        this_week_start = anchor_d - timedelta(days=anchor_d.weekday())
        return {"phrase": matched_phrase, "start": _day(this_week_start), "end": _day(anchor_d), "anchorless": False}

    if _RELATIVE_LAST_MONTH_RE.search(question):
        first_of_this_month = anchor_d.replace(day=1)
        last_of_prev_month = first_of_this_month - timedelta(days=1)
        first_of_prev_month = last_of_prev_month.replace(day=1)
        return {"phrase": matched_phrase, "start": _day(first_of_prev_month), "end": _day(last_of_prev_month), "anchorless": False}

    if _RELATIVE_THIS_MONTH_RE.search(question):
        first_of_this_month = anchor_d.replace(day=1)
        return {"phrase": matched_phrase, "start": _day(first_of_this_month), "end": _day(anchor_d), "anchorless": False}

    return None  # unreachable: matched_phrase implies one of the branches above fired


_EVENT_TS_SOURCES: list[tuple[type, tuple[str, ...]]] = [
    (FocusEventRow, ("timestamp",)),
    (CrashEventRow, ("timestamp",)),
    (AnrRow, ("timestamp",)),
    (TombstoneRow, ("timestamp",)),
    (WifiEventRow, ("timestamp",)),
    (ProcessKillEventRow, ("timestamp",)),
    (SelinuxDenialRow, ("timestamp",)),
    (CdmPairingEventRow, ("timestamp",)),
    (GnssSignalIntervalRow, ("start_timestamp", "end_timestamp")),
    (ProcessMemorySampleRow, ("timestamp",)),
    (BtHciSummaryRow, ("first_timestamp", "last_timestamp")),
    (BtHciEventRow, ("timestamp",)),
    (PacketCaptureSummaryRow, ("first_timestamp", "last_timestamp")),
]


def collect_capture_spans(session: Session, captures: list[Capture]) -> list[dict]:
    """Per-capture calendar min/max from persisted timestamps."""
    if not captures:
        return []
    ids = [c.id for c in captures if c.id is not None]
    by_id: dict[int, list[CalendarDay]] = {cid: [] for cid in ids}
    filenames = {c.id: c.original_filename for c in captures}

    for cap in captures:
        if cap.id is None or cap.captured_at is None:
            continue
        day = parse_timestamp_day(cap.captured_at)
        if day is not None:
            by_id[cap.id].append(day)

    for model, fields in _EVENT_TS_SOURCES:
        rows = session.exec(select(model).where(model.capture_id.in_(ids))).all()
        for row in rows:
            bucket = by_id.get(row.capture_id)
            if bucket is None:
                continue
            for field in fields:
                day = parse_timestamp_day(getattr(row, field, None))
                if day is not None:
                    bucket.append(day)

    spans = []
    for cid, days in by_id.items():
        if not days:
            spans.append({
                "capture_id": cid,
                "original_filename": filenames.get(cid),
                "first_date": None,
                "last_date": None,
            })
            continue
        first = min(days, key=lambda d: d.as_date())
        last = max(days, key=lambda d: d.as_date())
        spans.append({
            "capture_id": cid,
            "original_filename": filenames.get(cid),
            "first_date": first.display(),
            "last_date": last.display(),
            "_first": first,
            "_last": last,
        })
    spans.sort(key=lambda s: (
        s["_first"].as_date() if s.get("_first") else date.max,
        s["capture_id"],
    ))
    return spans


def _dated_spans(spans: list[dict]) -> list[dict]:
    return [s for s in spans if s.get("_first") is not None]


def _yearless_display(d: date, yearless: bool) -> str:
    day = CalendarDay(d.month, d.day, None if yearless else d.year)
    return day.display()


def _coverage_gaps(dated: list[dict]) -> list[dict]:
    """Holes between per-capture spans. min/max across captures is not a span."""
    if len(dated) < 2:
        return []
    ordered = sorted(dated, key=lambda s: (s["_first"].as_date(), s["capture_id"]))
    gaps = []
    cursor_end = ordered[0]["_last"].as_date()
    cursor = ordered[0]
    for span in ordered[1:]:
        start = span["_first"].as_date()
        end = span["_last"].as_date()
        if start <= cursor_end + timedelta(days=1):
            if end > cursor_end:
                cursor_end = end
                cursor = span
            continue
        yearless = cursor["_last"].year is None or span["_first"].year is None
        gap_from = cursor_end + timedelta(days=1)
        gap_to = start - timedelta(days=1)
        gaps.append({
            "after_date": cursor["_last"].display(),
            "before_date": span["_first"].display(),
            "gap_first_date": _yearless_display(gap_from, yearless),
            "gap_last_date": _yearless_display(gap_to, yearless),
            "after_capture_id": cursor["capture_id"],
            "before_capture_id": span["capture_id"],
        })
        cursor_end = end
        cursor = span
    return gaps


def _day_in_span(day: CalendarDay, span: dict) -> bool:
    return span["_first"].as_date() <= day.as_date() <= span["_last"].as_date()


def _public_span(span: dict) -> dict:
    return {
        "capture_id": span["capture_id"],
        "original_filename": span["original_filename"],
        "first_date": span["first_date"],
        "last_date": span["last_date"],
    }


def _range_phrase(dated: list[dict]) -> str:
    first = min(dated, key=lambda s: s["_first"].as_date())["_first"].display()
    last = max(dated, key=lambda s: s["_last"].as_date())["_last"].display()
    if first == last:
        return first
    return f"{first} through {last}"


def _per_capture_phrase(dated: list[dict]) -> str:
    bits = []
    for span in dated:
        if span["first_date"] == span["last_date"]:
            bits.append(span["first_date"])
        else:
            bits.append(f"{span['first_date']} through {span['last_date']}")
    return " and ".join(bits)


def _range_overlaps_gaps(start_d: date, end_d: date, gaps: list[dict]) -> bool:
    for gap in gaps:
        gap_first = parse_timestamp_day(gap["gap_first_date"])
        gap_last = parse_timestamp_day(gap["gap_last_date"])
        if gap_first and gap_last and start_d <= gap_last.as_date() and end_d >= gap_first.as_date():
            return True
    return False


def _build_relative_range_coverage(coverage: dict, relative: dict, dated: list[dict], gaps: list[dict]) -> dict:
    phrase = relative["phrase"]
    coverage["question_relative_phrase"] = phrase

    if relative["anchorless"]:
        coverage["relation"] = "unknown"
        coverage["statement"] = (
            f'The question refers to "{phrase}", but loaded captures have no timestamped '
            f"events to anchor that phrase to, so its coverage cannot be determined."
        )
        return coverage

    start_day: CalendarDay = relative["start"]
    end_day: CalendarDay = relative["end"]
    coverage["question_range"] = {"start": start_day.display(), "end": end_day.display(), "phrase": phrase}
    window_phrase = f'"{phrase}" ({start_day.display()} through {end_day.display()})'

    if not dated:
        coverage["relation"] = "unknown"
        coverage["statement"] = (
            f"The question refers to {window_phrase}, but loaded captures have no timestamped "
            f"events, so coverage cannot be determined."
        )
        return coverage

    start_d, end_d = start_day.as_date(), end_day.as_date()
    overall_min_d = min(s["_first"].as_date() for s in dated)
    overall_max_d = max(s["_last"].as_date() for s in dated)
    overlapping = [s for s in dated if not (end_d < s["_first"].as_date() or start_d > s["_last"].as_date())]

    if not overlapping:
        coverage["relation"] = "outside"
        coverage["statement"] = (
            f"The question refers to {window_phrase}, which falls entirely outside loaded "
            f"captures ({_range_phrase(dated)}). Nothing from that window was checked."
        )
        return coverage

    fully_inside = (
        start_d >= overall_min_d
        and end_d <= overall_max_d
        and not _range_overlaps_gaps(start_d, end_d, gaps)
    )
    if fully_inside:
        coverage["relation"] = "inside"
        coverage["statement"] = (
            f"The question refers to {window_phrase}, which is covered by loaded captures "
            f"({_range_phrase(dated)}). This window was checked in the loaded captures."
        )
    else:
        coverage["relation"] = "partial"
        coverage["statement"] = (
            f"The question refers to {window_phrase}, which only partially overlaps loaded "
            f"captures ({_range_phrase(dated)}); part of that window falls outside what was "
            f"captured. Only the overlapping portion was actually checked."
        )
    return coverage


def build_capture_coverage(
    session: Session, captures: list[Capture], question: str,
) -> dict:
    parsed = parse_question_date(question)
    spans = collect_capture_spans(session, captures)
    dated = _dated_spans(spans)
    gaps = _coverage_gaps(dated)

    overall_first = overall_last = None
    overall_last_day: CalendarDay | None = None
    if dated:
        overall_first = min(dated, key=lambda s: s["_first"].as_date())["_first"].display()
        last_span = max(dated, key=lambda s: s["_last"].as_date())
        overall_last = last_span["_last"].display()
        overall_last_day = last_span["_last"]

    coverage = {
        "captures": [_public_span(s) for s in spans],
        "overall_first_date": overall_first,
        "overall_last_date": overall_last,
        "gaps": gaps,
        "question_date": parsed["display"],
        "question_date_parse": parsed["parse"],
        "relation": None,
        "statement": None,
    }

    if parsed["parse"] == "absent":
        # No literal date -- try a relative phrase ("last week", "yesterday",
        # ...) anchored to the captures' own last dated event before giving up.
        relative = parse_relative_question_range(question, overall_last_day)
        if relative is None:
            return coverage
        return _build_relative_range_coverage(coverage, relative, dated, gaps)

    if parsed["parse"] == "unparsed":
        coverage["statement"] = (
            "A date in the question could not be parsed reliably, so no "
            "capture-coverage claim is made."
        )
        return coverage

    day: CalendarDay = parsed["day"]
    if not dated:
        coverage["relation"] = "unknown"
        coverage["statement"] = (
            f"Loaded captures have no timestamped events, so coverage of the "
            f"requested date {day.display()} cannot be determined."
        )
        return coverage

    matching = [s for s in dated if _day_in_span(day, s)]
    overall_min_d = min(s["_first"].as_date() for s in dated)
    overall_max_d = max(s["_last"].as_date() for s in dated)
    asked = day.as_date()

    if matching:
        coverage["relation"] = "inside"
        # Must not use gap/outside wording -- the date was covered.
        coverage["statement"] = (
            f"The requested date {day.display()} is covered by loaded captures "
            f"({_range_phrase(matching)}). The date was checked in the loaded captures."
        )
        return coverage

    if asked < overall_min_d or asked > overall_max_d:
        coverage["relation"] = "outside"
        coverage["statement"] = (
            f"Loaded captures cover {_range_phrase(dated)}. "
            f"The requested date {day.display()} is outside that range."
        )
        return coverage

    coverage["relation"] = "in_gap"
    containing = None
    for gap in gaps:
        gap_first = parse_timestamp_day(gap["gap_first_date"])
        gap_last = parse_timestamp_day(gap["gap_last_date"])
        if gap_first and gap_last and gap_first.as_date() <= asked <= gap_last.as_date():
            containing = gap
            break
    if containing:
        coverage["statement"] = (
            f"The requested date {day.display()} falls in a coverage gap between "
            f"{containing['after_date']} and {containing['before_date']} "
            f"(gap {containing['gap_first_date']} through {containing['gap_last_date']}). "
            f"Loaded captures cover {_per_capture_phrase(dated)}, not the days between. "
            f"Overall min/max {_range_phrase(dated)} spans that hole."
        )
    else:
        coverage["statement"] = (
            f"The requested date {day.display()} is not covered by any loaded capture "
            f"(per-capture coverage: {_per_capture_phrase(dated)})."
        )
    return coverage

