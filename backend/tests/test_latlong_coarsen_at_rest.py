"""#95: stored latitude/longitude are coarsened to 2 decimal degrees at rest.

Synthetic coordinates only (well-known public map examples and constructed
half-cases). Parser output and in-memory diagnosis stay at full precision.
No backfill, no identifier scrubbing.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import app
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


# ---------------------------------------------------------------- API leak

# Unique digit tails of the network fix in _SYNTHETIC_LOCATION_LINES, plus
# the exact decimal strings. Coarsened forms (37.77, -122.42) must not
# make these pass.
_FULL_PRECISION_NEEDLES = ("37.774929", "-122.419416", "774929", "419416")

_SYNTHETIC_LOCATION_BUGREPORT = (
    "DUMP OF SERVICE location:\n"
    + "\n".join(_SYNTHETIC_LOCATION_LINES)
    + "\n--------- 0.001s was the duration of dumpsys location\n"
)


@pytest.fixture
def api_client():
    # Same StaticPool pattern as test_api_user_flows: an in-memory SQLite
    # DB otherwise vanishes when TestClient opens a new connection per
    # request.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _override_session
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def _serialized(payload) -> str:
    if hasattr(payload, "text"):
        parts = [payload.text]
        try:
            parts.append(json.dumps(payload.json(), default=str))
        except ValueError:
            pass
        return "\n".join(parts)
    return json.dumps(payload, default=str)


def _assert_no_full_precision(payload, label: str) -> None:
    blob = _serialized(payload)
    for needle in _FULL_PRECISION_NEEDLES:
        assert needle not in blob, (
            f"{label} leaked full-precision coordinate {needle!r}"
        )


def test_full_precision_coords_absent_from_upload_summary_merged_and_llm_bundle(api_client):
    """FE should-fix on #125: full-precision values must not appear in any
    response built from a capture that went through the real upload/persist
    path. The source fixture is checked first so a missed parse cannot
    make this pass vacuously.
    """
    fixture = _SYNTHETIC_LOCATION_BUGREPORT
    for needle in _FULL_PRECISION_NEEDLES:
        assert needle in fixture, f"source fixture missing {needle!r}"

    upload = api_client.post(
        "/api/captures",
        data={"device_label": "synthetic-latlong-device"},
        files={"file": ("location.txt", fixture.encode(), "text/plain")},
    )
    assert upload.status_code == 200, upload.text
    capture_id = upload.json()["capture_id"]
    _assert_no_full_precision(upload, "upload response")

    summary = api_client.get(f"/api/captures/{capture_id}/summary")
    assert summary.status_code == 200, summary.text
    providers = {
        p["name"]: p for p in summary.json()["location_snapshot"]["providers"]
    }
    assert providers["network"]["latitude"] == 37.77
    assert providers["network"]["longitude"] == -122.42
    _assert_no_full_precision(summary, "capture summary response")

    merged = api_client.get("/api/devices/synthetic-latlong-device/summary")
    assert merged.status_code == 200, merged.text
    merged_providers = {
        p["name"]: p for p in merged.json()["location_snapshot"]["providers"]
    }
    assert merged_providers["network"]["latitude"] == 37.77
    assert merged_providers["network"]["longitude"] == -122.42
    _assert_no_full_precision(merged, "merged summary response")

    diagnose = api_client.post(
        f"/api/captures/{capture_id}/diagnose",
        data={"question": "What was the last GPS latitude?", "provider": "stub"},
    )
    assert diagnose.status_code == 200, diagnose.text
    bundle = diagnose.json()["bundle"]
    assert "location_snapshot_evidence" in bundle
    _assert_no_full_precision(diagnose, "diagnose HTTP response")
    _assert_no_full_precision(bundle, "LLM bundle from reasoning.py")
