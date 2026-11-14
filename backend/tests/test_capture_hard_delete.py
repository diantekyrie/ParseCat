"""#95: capture delete is a real hard delete (all capture_id rows gone).

Synthetic fixtures only. No Render wipe, no lat/long policy change.
"""
from __future__ import annotations

import json

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.db import get_session
from app.main import app
from tests.conftest import TEST_USER_ID, auth_headers
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
    # SessionAuthMiddleware gates every /api/* route on this branch -- a
    # bare TestClient(app) 401s before the route body (and _owned_capture's
    # ownership check) ever runs. See tests/conftest.py's auth_headers().
    with TestClient(app, headers=auth_headers()) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def delete_enabled(monkeypatch):
    """Turn the PARSECAT_ENABLE_CAPTURE_DELETE gate ON for a test.

    The route is OFF by default (returns 404), so any test that exercises a
    *successful* DELETE through the endpoint must opt in here. Tests of the
    service function hard_delete_capture() don't need this -- the flag only
    gates the HTTP route.
    """
    monkeypatch.setenv("PARSECAT_ENABLE_CAPTURE_DELETE", "1")


def _metadata_capture_fk_tables() -> dict[str, set[str]]:
    """The expected cascade set, derived INDEPENDENTLY of hard_delete's own
    discovery (capture_id_tables): walk SQLModel/SQLAlchemy metadata and keep
    every table (not Capture) with a foreign key whose target is the capture
    table, mapping table name -> set of local column names holding that FK.

    This is deliberately NOT a call into capture_id_tables() so the coverage
    assertions can catch the two ways that function could silently drift:
    a new FK table it fails to pick up, and an FK under a column name other
    than ``capture_id`` (which it keys on).
    """
    from app.models import db_models  # noqa: F401  (register tables)

    out: dict[str, set[str]] = {}
    for table in SQLModel.metadata.sorted_tables:
        if table.name == "capture":
            continue
        for fk in table.foreign_keys:
            if fk.column.table.name == "capture":
                out.setdefault(table.name, set()).add(fk.parent.name)
    return out


def _synthetic_value(column):
    """A type-appropriate non-null value for seeding an arbitrary column.

    Uses the column's generic ``_type_affinity`` so it handles custom
    TypeDecorators too (e.g. the AwareUTCDateTime wrapper on created_at /
    added_at, whose python_type is an opaque ``object``).
    """
    import datetime as _dt

    try:
        affinity = column.type._type_affinity
    except AttributeError:  # pragma: no cover - defensive
        affinity = None

    if affinity is not None and issubclass(affinity, sa.Boolean):
        return False
    if affinity is not None and issubclass(affinity, sa.Integer):
        return 1
    if affinity is not None and issubclass(affinity, (sa.Float, sa.Numeric)):
        return 1.0
    if affinity is not None and issubclass(affinity, sa.DateTime):
        return _dt.datetime.now(_dt.timezone.utc)
    if affinity is not None and issubclass(affinity, sa.Date):
        return _dt.date.today()
    return "synthetic"


def _seed_one_row_in_every_fk_table(session, capture_id: int) -> list[str]:
    """Insert exactly one row keyed to ``capture_id`` into EVERY table that
    has a capture FK, synthesizing values for all non-null columns.

    FK enforcement is off on the in-memory test engine, so the synthetic
    values in other FK columns don't need to reference real parent rows.
    Returns the list of seeded table names.
    """
    seeded: list[str] = []
    fk_tables = _metadata_capture_fk_tables()
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in fk_tables:
            continue
        values = {}
        for column in table.columns:
            if column.name in fk_tables[table.name]:
                values[column.name] = capture_id
                continue
            # Let the autoincrement integer PK assign itself.
            if column.primary_key and len(table.primary_key.columns) == 1:
                continue
            if column.nullable or column.default is not None or column.server_default is not None:
                continue
            values[column.name] = _synthetic_value(column)
        session.execute(table.insert().values(**values))
        seeded.append(table.name)
    session.commit()
    return seeded


def _device(session, label="synthetic-hard-delete-phone"):
    # owner_user_id must match auth_headers()'s TEST_USER_ID, or
    # delete_capture's _owned_capture() ownership check 404s the HTTP-level
    # tests even though the capture is real (this branch scopes every
    # capture route through its owning Device -- see routes.py).
    device = Device(label=label, owner_user_id=TEST_USER_ID)
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

    # Equality (not ">= 30") against a set derived INDEPENDENTLY from the
    # metadata foreign keys -- so the day someone adds a 37th capture-keyed
    # table and this set grows, the cascade either covers it or this fails.
    expected = set(_metadata_capture_fk_tables())
    assert expected  # sanity: the metadata really does have capture FK tables
    assert names == expected


def test_every_capture_fk_uses_the_capture_id_column_name():
    """The cascade keys on the ``capture_id`` column name (capture_id_tables
    only looks for a 'capture_id' column). A table that references capture
    under a DIFFERENTLY named FK column would be silently skipped by the
    delete, leaving orphaned PII-bearing rows behind.

    If such a table is ever added, this test fails loudly: either rename the
    column to follow the convention, or teach hard_delete.capture_id_tables()
    to discover FK columns by target rather than by name.
    """
    offenders = {
        table: sorted(cols)
        for table, cols in _metadata_capture_fk_tables().items()
        if cols != {"capture_id"}
    }
    assert offenders == {}, (
        "capture FK(s) under non-'capture_id' column name(s) -- the cascade "
        f"would miss these rows: {offenders}"
    )


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


def test_hard_delete_clears_a_row_in_every_capture_fk_table(session):
    """Seed one row in EVERY capture-keyed table (all 36), then verify the
    delete clears all of them -- and verify it INDEPENDENTLY of the delete's
    own discovery function by re-counting each table listed in the metadata
    FK set directly, not via tables_referencing_capture()."""
    device = _device(session)
    cap = _capture(session, device)
    cid = cap.id

    seeded = _seed_one_row_in_every_fk_table(session, cid)
    # We really did populate the full set, not just a handful.
    assert set(seeded) == set(_metadata_capture_fk_tables())
    assert len(seeded) >= 36

    # Pre-condition: every one of those tables has the row.
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in _metadata_capture_fk_tables():
            continue
        count = session.execute(
            sa.select(sa.func.count()).select_from(table).where(table.c.capture_id == cid)
        ).scalar_one()
        assert count == 1, f"seed failed for {table.name}"

    assert hard_delete_capture(session, cid) is True

    # Independent verification: walk the metadata FK set ourselves and assert
    # zero remaining rows per table (not a call into capture_id_tables).
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in _metadata_capture_fk_tables():
            continue
        count = session.execute(
            sa.select(sa.func.count()).select_from(table).where(table.c.capture_id == cid)
        ).scalar_one()
        assert count == 0, f"{table.name} still has rows for the deleted capture"
    assert session.get(Capture, cid) is None


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


def test_production_engine_has_secure_delete_on():
    """The app engine zeroes freed pages on delete (PRAGMA secure_delete=ON),
    so hard_delete_capture actually scrubs PII-bearing bytes rather than
    leaving them in reusable free pages."""
    from app.db import engine as app_engine

    with app_engine.connect() as conn:
        value = conn.execute(sa.text("PRAGMA secure_delete")).scalar_one()
    # SQLite reports secure_delete as 1 when ON.
    assert value == 1


def test_delete_endpoint_returns_404_afterward(client, session, delete_enabled):
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
    # Re-deleting an already-deleted capture (flag still ON) is "Unknown
    # capture" 404, not the flag-off 404.
    assert client.delete(f"/api/captures/{cid}").status_code == 404


def test_delete_endpoint_404s_and_leaves_intact_for_another_users_capture(
    session, delete_enabled,
):
    """#122's ownership gap, closed here: the auth token in `client` carries
    TEST_USER_ID, but a capture owned by a DIFFERENT user must 404 the same
    way an unknown id does -- same _owned_capture() scoping as every other
    /captures/{id} route -- and the capture must survive the attempt."""
    other_user_device = Device(label="someone-elses-phone", owner_user_id=TEST_USER_ID + 1)
    session.add(other_user_device)
    session.commit()
    session.refresh(other_user_device)
    cap = _capture(session, other_user_device)
    _seed_dependent_rows(session, cap.id)
    cid = cap.id

    def _override_session():
        yield session

    app.dependency_overrides[get_session] = _override_session
    try:
        with TestClient(app, headers=auth_headers()) as other_client:
            resp = other_client.delete(f"/api/captures/{cid}")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 404
    assert session.get(Capture, cid) is not None
    assert tables_referencing_capture(session, cid)  # still non-empty


def test_delete_endpoint_then_scan_returns_404(client, session, delete_enabled):
    """After a successful delete, a follow-up scan for that capture 404s."""
    device = _device(session)
    cap = _capture(session, device)
    _seed_dependent_rows(session, cap.id)
    cid = cap.id

    assert client.delete(f"/api/captures/{cid}").status_code == 200

    assert client.post(f"/api/captures/{cid}/scan").status_code == 404
    assert client.get(f"/api/captures/{cid}/summary").status_code == 404


def test_delete_unknown_capture_is_404(client, delete_enabled):
    assert client.delete("/api/captures/999999").status_code == 404


def test_delete_endpoint_404_when_flag_off(client, session, monkeypatch):
    """With the gate OFF (the default), the route behaves as if it does not
    exist: 404, not 403, and the capture is left completely intact."""
    monkeypatch.delenv("PARSECAT_ENABLE_CAPTURE_DELETE", raising=False)

    device = _device(session)
    cap = _capture(session, device)
    _seed_dependent_rows(session, cap.id)
    cid = cap.id

    resp = client.delete(f"/api/captures/{cid}")
    assert resp.status_code == 404

    # The capture and its rows are untouched -- nothing was deleted.
    assert session.get(Capture, cid) is not None
    assert tables_referencing_capture(session, cid)  # still non-empty


def test_delete_endpoint_flag_off_values_are_404(client, session, monkeypatch):
    """Non-truthy flag values (empty, '0', 'false', 'off', garbage) all keep
    the route 404; only truthy values enable it."""
    device = _device(session)
    cap = _capture(session, device)
    cid = cap.id

    for off_value in ("", "0", "false", "no", "off", "nope"):
        monkeypatch.setenv("PARSECAT_ENABLE_CAPTURE_DELETE", off_value)
        assert client.delete(f"/api/captures/{cid}").status_code == 404
        assert session.get(Capture, cid) is not None

    # And a truthy value (mixed case) enables it.
    monkeypatch.setenv("PARSECAT_ENABLE_CAPTURE_DELETE", "YeS")
    assert client.delete(f"/api/captures/{cid}").status_code == 200
