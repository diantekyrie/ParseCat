"""#95: stored latitude/longitude are coarsened to 2 decimal degrees at rest.

Synthetic coordinates only (well-known public map examples and constructed
half-cases). Parser output and in-memory diagnosis stay at full precision.
No backfill, no identifier scrubbing.
"""
from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import LocationProviderRow
from app.parsers.base import LocationProviderState, LocationSnapshot, ParsedCapture, SourceRef
from app.parsers.location import parse_location_dump
from app.parsers.section_extractor import Section
from app.services.persistence import coarsen_lat_long, persist_capture
from app.services.summary import build_capture_summary


# ---------------------------------------------------------------- unit


@pytest.mark.parametrize(
    "value, expected",
    [
        (37.774929, 37.77),
        (-122.419416, -122.42),
        (37.77, 37.77),
        (-122.42, -122.42),
        (0.0, 0.0),
        # ROUND_HALF_EVEN: ties go to the even hundredth.
        (37.775, 37.78),
        (37.765, 37.76),
        (1.225, 1.22),
        (1.235, 1.24),
        (-122.415, -122.42),
        (-122.425, -122.42),
        (-1.225, -1.22),
        (-1.235, -1.24),
        (90.0, 90.0),
        (-180.0, -180.0),
    ],
)
def test_coarsen_lat_long_rounds_to_two_decimals(value, expected):
    assert coarsen_lat_long(value) == expected


def test_coarsen_lat_long_none_stays_none():
    assert coarsen_lat_long(None) is None


# ---------------------------------------------------------------- persist


_SRC = SourceRef(section="location", line_start=1, line_end=1)

# Synthetic dumpsys location fragment. Coordinates are public-map examples,
# not from a real capture.
_SYNTHETIC_LOCATION_LINES = """  Location Settings:
    Location: On
  Location Providers:
    network provider:
      user 0:
        last location=Location[network 37.774929,-122.419416 hAcc=16.568 et=+1h0m0s0ms]
    gps provider:
      user 0:
        last location=Location[gps 37.775000,-122.415000 hAcc=8.0 et=+1h0m0s0ms alt=10.0 {Bundle[{satellites=8, maxCn0=30, meanCn0=20}]}]
    passive provider:
      user 0:
        last location=Location[passive 0.0,0.0 hAcc=0.0 et=+1h0m0s0ms]
""".splitlines()


def _parsed_with_providers(*providers: LocationProviderState) -> ParsedCapture:
    parsed = ParsedCapture()
    parsed.location_snapshot = LocationSnapshot(
        location_enabled=True,
        gnss_hardware_model=None,
        providers=list(providers),
        app_usage=[],
        kpi=None,
        source_ref=_SRC,
    )
    return parsed


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_parser_keeps_full_precision_on_synthetic_dump():
    section = Section(
        name="location",
        priority=None,
        line_start=1,
        line_end=len(_SYNTHETIC_LOCATION_LINES),
        lines=_SYNTHETIC_LOCATION_LINES,
        kind="dumpsys",
    )
    snap = parse_location_dump(section)
    by_name = {p.name: p for p in snap.providers}
    assert by_name["network"].latitude == 37.774929
    assert by_name["network"].longitude == -122.419416
    assert by_name["gps"].latitude == 37.775000
    assert by_name["gps"].longitude == -122.415000


def test_persist_stores_coarsened_coords_and_leaves_parser_output_intact(session):
    section = Section(
        name="location",
        priority=None,
        line_start=1,
        line_end=len(_SYNTHETIC_LOCATION_LINES),
        lines=_SYNTHETIC_LOCATION_LINES,
        kind="dumpsys",
    )
    snap = parse_location_dump(section)
    parsed = ParsedCapture()
    parsed.location_snapshot = snap

    # Full precision before persist.
    by_name = {p.name: p for p in snap.providers}
    assert by_name["network"].latitude == 37.774929
    assert by_name["network"].longitude == -122.419416
    assert by_name["gps"].latitude == 37.775
    assert by_name["gps"].longitude == -122.415

    cap = persist_capture(session, "synthetic-device", "synthetic.txt", parsed)

    # In-memory parser output is unchanged after the write.
    assert by_name["network"].latitude == 37.774929
    assert by_name["network"].longitude == -122.419416
    assert by_name["gps"].latitude == 37.775
    assert by_name["gps"].longitude == -122.415

    rows = {
        r.name: r
        for r in session.exec(
            select(LocationProviderRow).where(LocationProviderRow.capture_id == cap.id)
        ).all()
    }
    assert rows["network"].latitude == 37.77
    assert rows["network"].longitude == -122.42
    # Halfway cases used ROUND_HALF_EVEN: 37.775 -> 37.78, -122.415 -> -122.42.
    assert rows["gps"].latitude == 37.78
    assert rows["gps"].longitude == -122.42
    assert rows["passive"].latitude == 0.0
    assert rows["passive"].longitude == 0.0

    # API summary reads the stored (coarsened) values, not the parser object.
    summary = build_capture_summary(session, cap.id)
    summary_by_name = {p["name"]: p for p in summary["location_snapshot"]["providers"]}
    assert summary_by_name["network"]["latitude"] == 37.77
    assert summary_by_name["network"]["longitude"] == -122.42
    assert summary_by_name["gps"]["latitude"] == 37.78
    assert summary_by_name["gps"]["longitude"] == -122.42


def test_missing_coords_stay_none_in_the_database(session):
    parsed = _parsed_with_providers(
        LocationProviderState(
            name="fused",
            last_fix_provider=None,
            latitude=None,
            longitude=None,
            horizontal_accuracy_m=None,
            satellites=None,
            max_cn0=None,
            mean_cn0=None,
            source_ref=_SRC,
        ),
        LocationProviderState(
            name="network",
            last_fix_provider="network",
            latitude=37.774929,
            longitude=None,
            horizontal_accuracy_m=16.5,
            satellites=None,
            max_cn0=None,
            mean_cn0=None,
            source_ref=_SRC,
        ),
    )
    cap = persist_capture(session, "synthetic-device", "synthetic.txt", parsed)
    rows = {
        r.name: r
        for r in session.exec(
            select(LocationProviderRow).where(LocationProviderRow.capture_id == cap.id)
        ).all()
    }
    assert rows["fused"].latitude is None
    assert rows["fused"].longitude is None
    assert rows["network"].latitude == 37.77
    assert rows["network"].longitude is None
    # In-memory object was not mutated.
    assert parsed.location_snapshot.providers[1].latitude == 37.774929
    assert parsed.location_snapshot.providers[1].longitude is None
