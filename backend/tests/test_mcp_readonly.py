"""Read-only MCP server: structured allowlist + privacy tests.

Synthetic fixtures only — no real captures / PII / live keys.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, SQLModel, create_engine

from app.mcp_server import (
    READONLY_TOOL_NAMES,
    WRITEISH_TOOL_NAME_FRAGMENTS,
    get_fact as tool_get_fact,
    get_verified_facts as tool_get_verified_facts,
    list_captures as tool_list_captures,
    mcp,
)
from app.models.db_models import (
    AnrRow,
    Capture,
    CdmPairingEventRow,
    CompanionDeviceAssociationRow,
    CrashEventRow,
    Device,
    DeviceInfoRow,
    KernelLogEventRow,
    SelinuxDenialRow,
    TombstoneRow,
    WifiEventRow,
)
from mcp.server.mcpserver.exceptions import ToolError
from app.services.mcp_readonly import (
    DEFAULT_FACT_LIMIT,
    DETAIL_WITHHELD,
    FACT_KIND_KEYS,
    MAX_FACT_LIMIT,
    MAX_IDENTIFIER_CHARS,
    MCP_REDACT_KEYS,
    CaptureNotFoundError,
    FactNotFoundError,
    assert_engine_is_readonly,
    get_fact,
    get_verified_facts,
    list_captures,
    open_readonly_engine,
    project_fact,
    scrub_allowlisted_text,
)


# Synthetic seeds — never real credentials or personal data.
FAKE_SSID = "ssid-mcp-test"
FAKE_BSSID = "aa:bb:cc:dd:ee:11"
FAKE_MAC = "aa:bb:cc:dd:ee:22"
FAKE_MAC_IN_TEXT = "aa:bb:cc:dd:ee:33"
FAKE_CDM_NAME = "Fake private watch"
FAKE_CDM_DEVICE = "Pixel Watch FE-Lab"
FAKE_EMAIL = "alice.mcp@example.com"
FAKE_PHONE = "+1-415-555-0199"
FAKE_LABEL = "mcp-synth-phone-label"
FAKE_FILENAME_A = "mcp-synth-report-A.zip"
FAKE_FILENAME_B = "mcp-synth-report-B.zip"
FAKE_SK = "sk-or-v1-mcpSYNTHETIC00000000000000000001"
FAKE_AIZA = "AIzaSyMcpSyntheticTestKey00000000001"
FAKE_GSK = "gsk_mcpSyntheticTestKey0000000000001"
FAKE_SSID_EMBED = "HomeNet-FE42"
FAKE_SERIAL_EMBED = "HT72C1A0FE001"
FAKE_LAT = "37.774900"
FAKE_LON = "-122.419400"
FAKE_DNS = "tracker.ads.example.com"
FAKE_PASSWORD = "s3cretFE"
FAKE_BEARER = "aabbccddee001122"
FAKE_TOKEN = "xyz123abcTOKEN01"

# Arch exact leak cases.
ARCH_LABEL_UNDERSCORE = "_private-lab-phone_"
ARCH_NESTED_LABEL = "phone"
ARCH_BARE_ALICE = "Alice"
ARCH_JANE = "Jane Doe"

# Over-redaction fixtures.
OVER_REDACT_FILE_12 = "12.txt"
OVER_REDACT_FILE_CRASH = "crash.zip"
LONG_PACKAGE = "com.example.abcdefghijklmnopqrstuvwxyzabcdef"
LONG_EXCEPTION = "com.example.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefException"
# >240 chars, still under MAX_IDENTIFIER_CHARS, valid Android package shape.
VERY_LONG_PACKAGE = "com.example." + ("v" * 300)

# Cat QA canaries (synthetic) — planted into identifier + free-text fields.
CAT_SSID = "CatCanarySSID"
CAT_MAC = "de:ad:be:ef:00:01"
CAT_SERIAL = "CATSERIAL001"
CAT_IP = "203.0.113.50"
CAT_EMAIL = "cat.canary@example.com"
CAT_PHONE = "+1-415-555-0182"
CAT_FILE = "cat-canary-report.zip"
CAT_LABEL = "cat-canary-label"
CAT_POISON = (
    f"{CAT_SSID} {CAT_MAC} {CAT_SERIAL} {CAT_IP} "
    f"{CAT_EMAIL} {CAT_PHONE} {CAT_FILE} {CAT_LABEL}"
)
CAT_CANARIES = (
    CAT_SSID, CAT_MAC, CAT_SERIAL, CAT_IP, CAT_EMAIL, CAT_PHONE, CAT_FILE, CAT_LABEL,
)


def _assert_no_forbidden(blob: str):
    lowered = blob.lower()
    for needle in (
        FAKE_SSID, FAKE_BSSID, FAKE_MAC, FAKE_MAC_IN_TEXT,
        FAKE_CDM_NAME, FAKE_CDM_DEVICE, FAKE_EMAIL, FAKE_PHONE, FAKE_LABEL,
        FAKE_FILENAME_A, FAKE_FILENAME_B,
        FAKE_SK, FAKE_AIZA, FAKE_GSK,
        FAKE_SSID_EMBED, FAKE_SERIAL_EMBED, FAKE_LAT, FAKE_LON, FAKE_DNS,
        FAKE_PASSWORD, FAKE_BEARER, FAKE_TOKEN,
        "ssid-sibling-only", "aa:bb:cc:dd:ee:99",
        "mcp-synth-report-A",
        ARCH_LABEL_UNDERSCORE, ARCH_BARE_ALICE, "Jane Doe",
        OVER_REDACT_FILE_12, OVER_REDACT_FILE_CRASH,
        "private-lab-phone",
        *CAT_CANARIES,
    ):
        assert needle.lower() not in lowered, f"leaked {needle!r}"
    # Arch nested / quoted forms (avoid matching the PII token [redacted-phone]).
    assert '{"label":"phone"}' not in blob
    assert '"label":"phone"' not in blob
    assert 'label="Jane Doe"' not in blob
    assert "label=Jane" not in blob
    # Trailing surname from label="Jane Doe" must not appear as its own leak.
    assert " Doe" not in blob and not blob.endswith("Doe")


@pytest.fixture
def writable_db(tmp_path: Path):
    """Writable SQLite with siblings, archived device, Arch/FE seeds."""
    db_path = tmp_path / "parsecat.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        active = Device(label=FAKE_LABEL, archived=False)
        alice = Device(label=ARCH_BARE_ALICE, archived=False)
        jane = Device(label=ARCH_JANE, archived=False)
        underscore = Device(label=ARCH_LABEL_UNDERSCORE, archived=False)
        archived = Device(label="mcp-archived-label", archived=True)
        for d in (active, alice, jane, underscore, archived):
            session.add(d)
        session.commit()
        for d in (active, alice, jane, underscore, archived):
            session.refresh(d)

        cap_a = Capture(device_id=active.id, original_filename=FAKE_FILENAME_A)
        cap_b = Capture(device_id=active.id, original_filename=FAKE_FILENAME_B)
        cap_12 = Capture(device_id=active.id, original_filename=OVER_REDACT_FILE_12)
        cap_crash_name = Capture(device_id=active.id, original_filename=OVER_REDACT_FILE_CRASH)
        cap_alice = Capture(device_id=alice.id, original_filename="alice-report.zip")
        cap_jane = Capture(device_id=jane.id, original_filename="jane-report.zip")
        cap_us = Capture(device_id=underscore.id, original_filename="us-report.zip")
        hidden = Capture(device_id=archived.id, original_filename="mcp-hidden.zip")
        for c in (
            cap_a, cap_b, cap_12, cap_crash_name, cap_alice, cap_jane, cap_us, hidden,
        ):
            session.add(c)
        session.commit()
        for c in (
            cap_a, cap_b, cap_12, cap_crash_name, cap_alice, cap_jane, cap_us, hidden,
        ):
            session.refresh(c)

        # Capture A: wifi reason 12 + CDM + crash with planted secrets/labels in message.
        session.add(WifiEventRow(
            capture_id=cap_a.id,
            timestamp="08-19 12:00:00.000",
            kind="disconnection",
            ssid=FAKE_SSID,
            bssid=FAKE_BSSID,
            reason_code=12,
            reason_name="Disassociated due to inactivity",
            locally_generated=False,
            roam=None,
            source_section="wifi",
            source_line_start=10,
            source_line_end=10,
        ))
        session.add(CompanionDeviceAssociationRow(
            capture_id=cap_a.id,
            association_id=1,
            mac_address=FAKE_MAC,
            display_name=FAKE_CDM_DEVICE,
            package_name="com.example.companion",
            device_profile="WATCH",
            self_managed=False,
            revoked=False,
            pending=False,
            trusted=True,
            time_approved=None,
            last_time_connected=None,
            currently_connected=True,
            source_section="cdm",
            source_line_start=1,
            source_line_end=1,
        ))
        session.add(CdmPairingEventRow(
            capture_id=cap_a.id,
            timestamp="08-19 12:05:00.000",
            level="I",
            tag="CDM",
            kind="association_approved",
            mac_address=FAKE_MAC,
            display_name=FAKE_CDM_DEVICE,
            package_name="com.example.companion",
            association_id=1,
            detail=(
                f"onAssociationApproved() name={FAKE_CDM_DEVICE} "
                f'label="{ARCH_JANE}" nested={{"label":"{ARCH_NESTED_LABEL}"}} '
                f"{ARCH_LABEL_UNDERSCORE} {ARCH_BARE_ALICE} "
                f"ssid={FAKE_SSID_EMBED} serial={FAKE_SERIAL_EMBED} "
                f"lat={FAKE_LAT} lon={FAKE_LON} dns_query={FAKE_DNS} "
                f"file={FAKE_FILENAME_A} label={FAKE_LABEL}"
            ),
            source_section="system_log",
            source_line_start=20,
            source_line_end=20,
        ))
        # Crash/ANR/kernel free text may be emitted (FE). Plant only values
        # that #96/#102 (+ MAC/secret KV) scrub — NOT stored labels/filenames
        # (those are planted on Device/Capture rows and in CDM detail, which
        # MCP drops rather than value-scrubbing).
        # Free-text seeds for FE ruling: present in DB, omitted by default from MCP.
        free_text_seed = (
            f"label={FAKE_LABEL} file={FAKE_FILENAME_A} "
            f"{ARCH_BARE_ALICE} {ARCH_JANE} {ARCH_LABEL_UNDERSCORE}"
        )
        crash_msg = (
            f"boom contact {FAKE_EMAIL} tel:{FAKE_PHONE} "
            f"key {FAKE_SK} also {FAKE_AIZA} and {FAKE_GSK} "
            f"mac {FAKE_MAC_IN_TEXT} "
            f"password={FAKE_PASSWORD} pwd={FAKE_PASSWORD} "
            f"Authorization: Bearer {FAKE_BEARER} token={FAKE_TOKEN} "
            f"{free_text_seed}"
        )
        session.add(CrashEventRow(
            capture_id=cap_a.id,
            timestamp="08-19 12:01:00.000",
            thread="main",
            package=LONG_PACKAGE,
            pid=42,
            exception_class=LONG_EXCEPTION,
            message=crash_msg,
            root_cause_class="CauseException",
            root_cause_message=f"root {free_text_seed}",
            root_cause_frame=None,
            source_section="system_log",
            source_line_start=100,
            source_line_end=120,
        ))
        session.add(AnrRow(
            capture_id=cap_a.id,
            filename="anr_2024",
            timestamp="08-19 12:02:00.000",
            subject=f"Input dispatching timed out ({FAKE_LABEL})",
            pid=43,
            package="com.example.app",
            reason=f"Input dispatching timed out {free_text_seed}",
            timeout_ms=5000,
            rss_kb=1000,
        ))
        session.add(KernelLogEventRow(
            capture_id=cap_a.id,
            boot_relative_sec=12.5,
            priority=3,
            priority_name="ERR",
            thread="kworker",
            message=f"kernel oops password={FAKE_PASSWORD} {free_text_seed}",
            is_panic_family=False,
            source_section="kernel",
            source_line_start=1,
            source_line_end=1,
        ))


        # Cat QA canary capture: poison every allowlisted string identifier field
        # plus free-text SSID/serial/IP/filename seeds. Ground truth keeps the poison;
        # MCP must withhold / scrub.
        cat_dev = Device(label=CAT_LABEL, archived=False)
        session.add(cat_dev)
        session.commit()
        session.refresh(cat_dev)
        cap_cat = Capture(device_id=cat_dev.id, original_filename=CAT_FILE)
        session.add(cap_cat)
        session.commit()
        session.refresh(cap_cat)
        session.add(DeviceInfoRow(
            capture_id=cap_cat.id,
            serial=CAT_SERIAL,
            manufacturer="Synth",
            model="CatQA",
        ))
        session.add(WifiEventRow(
            capture_id=cap_cat.id,
            timestamp="08-19 12:00:00.000",
            kind="disconnection",
            ssid=CAT_SSID,
            bssid=CAT_MAC,
            reason_code=3,
            reason_name=CAT_POISON,  # must be withheld (shape/pii)
            locally_generated=False,
            roam=None,
            source_section="wifi",
            source_line_start=1,
            source_line_end=1,
        ))
        session.add(CrashEventRow(
            capture_id=cap_cat.id,
            timestamp="08-19 12:01:00.000",
            thread=CAT_POISON,
            package=VERY_LONG_PACKAGE,
            pid=42,
            exception_class=CAT_POISON,
            message=(
                f"boom ssid={CAT_SSID} serial={CAT_SERIAL} ip={CAT_IP} "
                f"file={CAT_FILE} label={CAT_LABEL} {CAT_EMAIL}"
            ),
            root_cause_class=CAT_POISON,
            root_cause_message=f"root ssid={CAT_SSID} serial={CAT_SERIAL} ip={CAT_IP} file={CAT_FILE}",
            root_cause_frame=None,
            source_section="system_log",
            source_line_start=1,
            source_line_end=1,
        ))
        session.add(CrashEventRow(
            capture_id=cap_cat.id,
            timestamp="08-19 12:01:30.000",
            thread="main",
            package="com.example.ok",
            pid=43,
            exception_class="java.lang.RuntimeException",
            message=None,
            root_cause_class=None,
            root_cause_message=None,
            root_cause_frame=None,
            source_section="system_log",
            source_line_start=2,
            source_line_end=2,
        ))
        session.add(TombstoneRow(
            capture_id=cap_cat.id,
            filename="tombstone_00",
            modified_at="2024-01-01",
            timestamp="08-19 12:02:00.000",
            executable=CAT_POISON,
            package=CAT_POISON,
            pid=7,
            tid=8,
            signal_number=11,
            signal_name="SIGSEGV",
            signal_code=CAT_POISON,
        ))
        session.add(AnrRow(
            capture_id=cap_cat.id,
            filename="anr_cat",
            timestamp="08-19 12:03:00.000",
            subject="timed out",
            pid=9,
            package=CAT_POISON,
            reason=f"Input dispatching timed out ssid={CAT_SSID} serial={CAT_SERIAL} ip={CAT_IP} file={CAT_FILE}",
            timeout_ms=5000,
            rss_kb=100,
        ))
        session.add(KernelLogEventRow(
            capture_id=cap_cat.id,
            boot_relative_sec=1.0,
            priority=3,
            priority_name="ERR",
            thread=CAT_POISON,
            message=f"oops ssid={CAT_SSID} serial={CAT_SERIAL} ip={CAT_IP} file={CAT_FILE}",
            is_panic_family=False,
            source_section="kernel",
            source_line_start=1,
            source_line_end=1,
        ))
        session.add(SelinuxDenialRow(
            capture_id=cap_cat.id,
            timestamp="08-19 12:04:00.000",
            verdict="denied",
            permissions="read write getattr",
            source_domain="untrusted_app",
            target_type="app_data_file",
            target_class="file",
            app="com.example.app",
            comm="app_process",
            enforcing=True,
            source_section="selinux",
            source_line_start=1,
            source_line_end=1,
        ))
        session.add(CdmPairingEventRow(
            capture_id=cap_cat.id,
            timestamp="08-19 12:05:00.000",
            level="I",
            tag=CAT_POISON,
            kind="association_approved",
            mac_address=CAT_MAC,
            display_name=CAT_LABEL,
            package_name=CAT_POISON,
            association_id=1,
            detail="withheld",
            source_section="system_log",
            source_line_start=20,
            source_line_end=20,
        ))

        # Sibling B wifi only.
        session.add(WifiEventRow(
            capture_id=cap_b.id,
            timestamp="08-19 13:00:00.000",
            kind="disconnection",
            ssid="ssid-sibling-only",
            bssid="aa:bb:cc:dd:ee:99",
            reason_code=4,
            reason_name="Disassociated due to inactivity",
            locally_generated=True,
            roam=None,
            source_section="wifi",
            source_line_start=20,
            source_line_end=20,
        ))

        # Over-redaction probes: filename 12.txt / crash.zip must not mutate fields.
        session.add(WifiEventRow(
            capture_id=cap_12.id,
            timestamp="08-19 12:00:12.000",
            kind="disconnection",
            ssid="x",
            bssid="aa:bb:cc:dd:ee:10",
            reason_code=12,
            reason_name="reason twelve",
            locally_generated=False,
            roam=None,
            source_section="wifi",
            source_line_start=12,
            source_line_end=12,
        ))
        session.add(CrashEventRow(
            capture_id=cap_crash_name.id,
            timestamp="08-19 12:00:00.000",
            thread="main",
            package="com.example.crash",
            pid=12,
            exception_class="RuntimeException",
            message="app crash in module",
            root_cause_class=None,
            root_cause_message=None,
            root_cause_frame=None,
            source_section="system_log",
            source_line_start=1,
            source_line_end=1,
        ))

        # Alice / Jane / underscore label devices: crash with benign structured fields.
        for cap, label in (
            (cap_alice, ARCH_BARE_ALICE),
            (cap_jane, ARCH_JANE),
            (cap_us, ARCH_LABEL_UNDERSCORE),
        ):
            session.add(CrashEventRow(
                capture_id=cap.id,
                timestamp="08-19 12:00:00.000",
                thread="main",
                package="com.example.app",
                pid=1,
                exception_class="RuntimeException",
                message="ok synthetic crash message",
                root_cause_class=None,
                root_cause_message=None,
                root_cause_frame=None,
                source_section="system_log",
                source_line_start=1,
                source_line_end=1,
            ))

        session.commit()
        ids = {
            "db_path": db_path,
            "capture_a": cap_a.id,
            "capture_b": cap_b.id,
            "capture_12": cap_12.id,
            "capture_crash_name": cap_crash_name.id,
            "capture_cat": cap_cat.id,
            "capture_alice": cap_alice.id,
            "capture_jane": cap_jane.id,
            "capture_us": cap_us.id,
            "hidden": hidden.id,
        }
    engine.dispose()
    return ids


@pytest.fixture
def ro_session(writable_db, monkeypatch):
    db_path = writable_db["db_path"]
    monkeypatch.setenv("PARSECAT_DB_PATH", str(db_path))
    engine = open_readonly_engine(db_path)
    with Session(engine) as session:
        yield session, writable_db, engine


# --- unit helpers -----------------------------------------------------------

def test_scrub_allowlisted_text_redacts_secrets_not_numbers():
    raw = (
        f"email {FAKE_EMAIL} phone {FAKE_PHONE} "
        f"{FAKE_SK} mac {FAKE_MAC_IN_TEXT} "
        f"password={FAKE_PASSWORD} Authorization: Bearer {FAKE_BEARER}"
    )
    out = scrub_allowlisted_text(raw)
    assert out is not None
    assert FAKE_EMAIL not in out
    assert FAKE_SK not in out
    assert FAKE_MAC_IN_TEXT not in out
    assert FAKE_PASSWORD not in out
    assert FAKE_BEARER not in out
    # Does not eat bare numbers / the word crash.
    assert scrub_allowlisted_text("reason 12 at 08-19 12:00:12 crash") == (
        "reason 12 at 08-19 12:00:12 crash"
    )


def test_project_fact_fail_closed_drops_sibling_and_free_text_keys():
    sibling = {
        "category": "wifi",
        "timestamp": "t",
        "reason_code": 3,
        "capture_id": 99,
        "summary": "Wi-Fi disconnection",
        "detail": "secret",
        "ssid": FAKE_SSID,
    }
    assert project_fact(sibling, capture_id=1) is None

    ok = {
        "category": "wifi",
        "timestamp": "08-19 12:00:00.000",
        "kind": "disconnection",
        "reason_code": 12,
        "reason_name": "x",
        "capture_id": 1,
        "summary": f"CDM association present: {FAKE_CDM_NAME}",
        "detail": f"label={FAKE_LABEL}",
        "ssid": FAKE_SSID,
    }
    projected = project_fact(ok, capture_id=1)
    assert projected is not None
    assert "summary" not in projected
    assert "detail" not in projected
    assert "ssid" not in projected
    assert projected["reason_code"] == 12
    assert projected.get("note") == DETAIL_WITHHELD


def test_mcp_redact_keys_constant_still_lists_identifiers():
    for key in ("ssid", "bssid", "mac_address", "serial", "display_name", "label"):
        assert key in MCP_REDACT_KEYS


# --- RO engine --------------------------------------------------------------

def test_open_readonly_engine_rejects_writes(writable_db):
    engine = open_readonly_engine(writable_db["db_path"])
    assert_engine_is_readonly(engine)
    with engine.connect() as conn:
        with pytest.raises(OperationalError):
            conn.exec_driver_sql("CREATE TABLE should_fail (id INTEGER)")
            conn.commit()


def test_missing_db_does_not_create(tmp_path):
    missing = tmp_path / "nope.db"
    with pytest.raises(FileNotFoundError):
        open_readonly_engine(missing)
    assert not missing.exists()


# --- list / scope -----------------------------------------------------------

def test_list_captures_hides_archived_and_omits_label_filename(ro_session):
    session, ids, _ = ro_session
    payload = list_captures(session, limit=100)
    listed = {c["id"] for c in payload["captures"]}
    assert ids["capture_a"] in listed
    assert ids["hidden"] not in listed
    for cap in payload["captures"]:
        assert "label" not in cap
        assert "original_filename" not in cap
    _assert_no_forbidden(json.dumps(payload))


def test_get_verified_facts_excludes_sibling_capture(ro_session):
    session, ids, _ = ro_session
    payload = get_verified_facts(session, ids["capture_a"])
    assert {f.get("capture_id") for f in payload["facts"]} == {ids["capture_a"]}
    blob = json.dumps(payload)
    assert "ssid-sibling-only" not in blob


def test_get_fact_sibling_id_with_capture_a_not_found(ro_session):
    session, ids, _ = ro_session
    b_payload = get_verified_facts(session, ids["capture_b"])
    assert b_payload["facts"]
    b_fact_id = b_payload["facts"][0]["fact_id"]
    with pytest.raises(FactNotFoundError):
        get_fact(session, b_fact_id, capture_id=ids["capture_a"])
    found = get_fact(session, b_fact_id, capture_id=ids["capture_b"])
    assert found["fact"]["capture_id"] == ids["capture_b"]


# --- structured allowlist ---------------------------------------------------

def test_structured_facts_omit_spliced_identity_and_keep_codes(ro_session):
    session, ids, _ = ro_session
    payload = get_verified_facts(session, ids["capture_a"], limit=500)
    blob = json.dumps(payload)
    _assert_no_forbidden(blob)
    # No citation-walk free-text summary/detail channel.
    for fact in payload["facts"]:
        assert "summary" not in fact
        assert "detail" not in fact
        assert "untrusted_log_text" not in fact
        assert "ssid" not in fact
        assert "display_name" not in fact
        assert "original_filename" not in fact
        assert "device_label" not in fact
        assert set(fact.keys()) <= (
            {"fact_id", "category", "capture_id", "timestamp", "confidence", "source", "note"}
            | FACT_KIND_KEYS.get(fact["category"], frozenset())
        )

    wifi = [f for f in payload["facts"] if f["category"] == "wifi"]
    assert wifi and wifi[0]["reason_code"] == 12
    assert "Disassociated due to inactivity" in wifi[0]["reason_name"]

    pairing = [f for f in payload["facts"] if f["category"] == "pairing"]
    assert pairing
    for f in pairing:
        assert f.get("note") == DETAIL_WITHHELD
        assert FAKE_CDM_DEVICE not in json.dumps(f)

    crash = [f for f in payload["facts"] if f["category"] == "crash"]
    assert crash
    # Default: free text omitted.
    assert "message" not in crash[0]
    assert "root_cause_message" not in crash[0]
    assert crash[0]["package"] == LONG_PACKAGE
    assert crash[0]["exception_class"] == LONG_EXCEPTION


def test_arch_leak_cases_absent_from_all_tools(ro_session):
    """Arch: _private-lab-phone_, nested label JSON, Alice, Jane Doe / Doe."""
    session, ids, _ = ro_session
    blobs = [
        json.dumps(list_captures(session, limit=100)),
        tool_list_captures(offset=0, limit=100),
    ]
    for key in (
        "capture_a", "capture_alice", "capture_jane", "capture_us",
        "capture_12", "capture_crash_name",
    ):
        facts_json = tool_get_verified_facts(capture_id=ids[key], limit=500)
        blobs.append(facts_json)
        facts = json.loads(facts_json)["facts"]
        for fact in facts:
            one = tool_get_fact(fact_id=fact["fact_id"], capture_id=ids[key])
            blobs.append(one)

    for blob in blobs:
        _assert_no_forbidden(blob)


def test_over_redaction_filename_12_and_crash_survive(ro_session):
    session, ids, _ = ro_session
    # Filename 12.txt must not strip 12 from timestamp / reason_code.
    p12 = get_verified_facts(session, ids["capture_12"])
    wifi = [f for f in p12["facts"] if f["category"] == "wifi"]
    assert wifi
    assert wifi[0]["reason_code"] == 12
    assert wifi[0]["timestamp"] == "08-19 12:00:12.000"
    assert wifi[0]["source"]["line_start"] == 12
    blob12 = json.dumps(p12)
    assert OVER_REDACT_FILE_12 not in blob12
    # Explicit serialized-output assert (was missing/vacuous before).
    assert '"reason_code": 12' in blob12 or '"reason_code":12' in blob12
    ser = tool_get_verified_facts(capture_id=ids["capture_12"], limit=50)
    assert '"reason_code": 12' in ser or '"reason_code":12' in ser
    ser_obj = json.loads(ser)
    ser_wifi = [f for f in ser_obj["facts"] if f["category"] == "wifi"]
    assert ser_wifi and ser_wifi[0]["reason_code"] == 12

    # Filename crash.zip must not delete 'crash' from structured identifiers.
    # Free text (message) is omitted by default per FE ruling.
    pc = get_verified_facts(session, ids["capture_crash_name"])
    crash = [f for f in pc["facts"] if f["category"] == "crash"]
    assert crash
    assert crash[0]["package"] == "com.example.crash"
    assert "crash" in crash[0]["package"]
    assert "message" not in crash[0]
    assert OVER_REDACT_FILE_CRASH not in json.dumps(pc)

    # get_fact loops every fixture fact for these captures.
    for key in ("capture_12", "capture_crash_name"):
        facts = get_verified_facts(session, ids[key])["facts"]
        assert facts
        for fact in facts:
            one = get_fact(session, fact["fact_id"], capture_id=ids[key])
            blob = json.dumps(one)
            assert OVER_REDACT_FILE_12 not in blob
            assert OVER_REDACT_FILE_CRASH not in blob
            if key == "capture_12" and fact["category"] == "wifi":
                assert one["fact"]["reason_code"] == 12
                assert "12:00:12" in one["fact"]["timestamp"]
            if key == "capture_crash_name" and fact["category"] == "crash":
                assert "crash" in one["fact"]["package"]
                assert "message" not in one["fact"]


def test_fe_free_text_redaction_all_three_tools(ro_session):
    """FE: plant forbidden values; none appear in serialized tool JSON."""
    session, ids, _ = ro_session
    list_json = tool_list_captures(offset=0, limit=100)
    facts_json = tool_get_verified_facts(capture_id=ids["capture_a"], limit=500)
    facts_obj = json.loads(facts_json)
    assert facts_obj["facts"]

    for fact in facts_obj["facts"]:
        one_json = tool_get_fact(fact_id=fact["fact_id"], capture_id=ids["capture_a"])
        for blob in (list_json, facts_json, one_json):
            _assert_no_forbidden(blob)
            # (a) CDM device names
            assert FAKE_CDM_DEVICE not in blob
            # (b) SSID / serial / lat-long / DNS
            assert FAKE_SSID_EMBED not in blob
            assert FAKE_SERIAL_EMBED not in blob
            assert FAKE_LAT not in blob
            assert FAKE_LON not in blob
            assert FAKE_DNS not in blob
            # (c) labels / filenames
            assert FAKE_LABEL not in blob
            assert FAKE_FILENAME_A not in blob
            # (d) passwords / bearer / token
            assert FAKE_PASSWORD not in blob
            assert FAKE_BEARER not in blob
            assert FAKE_TOKEN not in blob

    assert any(f.get("category") == "wifi" for f in facts_obj["facts"])
    assert any(f.get("category") == "pairing" for f in facts_obj["facts"])


def test_get_verified_facts_unknown_and_archived(ro_session):
    session, ids, _ = ro_session
    with pytest.raises(CaptureNotFoundError):
        get_verified_facts(session, 999999)
    with pytest.raises(CaptureNotFoundError):
        get_verified_facts(session, ids["hidden"])


def test_get_verified_facts_limit_and_offset(ro_session):
    session, ids, _ = ro_session
    payload = get_verified_facts(session, ids["capture_a"], limit=1, offset=0)
    assert payload["limit"] == 1
    assert payload["returned"] <= 1
    over = get_verified_facts(session, ids["capture_a"], limit=MAX_FACT_LIMIT + 1000)
    assert over["limit"] == MAX_FACT_LIMIT


def test_mcp_server_tool_list_has_no_write_tools():
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert names == set(READONLY_TOOL_NAMES)
    for name in names:
        lowered = name.lower()
        for frag in WRITEISH_TOOL_NAME_FRAGMENTS:
            assert frag not in lowered



def test_long_package_and_exception_survive_verbatim(ro_session):
    """Blocker 2: key-token heuristic must not touch structured identifiers."""
    session, ids, _ = ro_session
    # Prove the heuristic would mangle the package if applied.
    mangled = scrub_allowlisted_text(LONG_PACKAGE)
    assert mangled != LONG_PACKAGE

    facts_json = tool_get_verified_facts(capture_id=ids["capture_a"], limit=500)
    list_json = tool_list_captures(offset=0, limit=100)
    facts = json.loads(facts_json)["facts"]
    crash = [f for f in facts if f["category"] == "crash"]
    assert crash
    assert crash[0]["package"] == LONG_PACKAGE
    assert crash[0]["exception_class"] == LONG_EXCEPTION

    one_json = tool_get_fact(fact_id=crash[0]["fact_id"], capture_id=ids["capture_a"])
    # list_captures has no per-fact package/exception; check fact tools only.
    assert LONG_PACKAGE not in list_json  # list has counts only
    for blob in (facts_json, one_json):
        assert LONG_PACKAGE in blob
        assert LONG_EXCEPTION in blob
    one = json.loads(one_json)["fact"]
    assert one["package"] == LONG_PACKAGE
    assert one["exception_class"] == LONG_EXCEPTION
    # Direct API path too.
    api = get_verified_facts(session, ids["capture_a"])
    api_crash = [f for f in api["facts"] if f["category"] == "crash"][0]
    assert api_crash["package"] == LONG_PACKAGE
    assert api_crash["exception_class"] == LONG_EXCEPTION


def test_free_text_omitted_by_default(ro_session):
    """FE ruling: crash/ANR/kernel free text dropped unless env flag is 1."""
    session, ids, _ = ro_session
    blobs = [tool_list_captures(offset=0, limit=100)]
    facts_json = tool_get_verified_facts(capture_id=ids["capture_a"], limit=500)
    blobs.append(facts_json)
    facts = json.loads(facts_json)["facts"]
    for fact in facts:
        assert "message" not in fact
        assert "root_cause_message" not in fact
        assert "reason" not in fact or fact["category"] != "anr"
        if fact["category"] == "anr":
            assert "reason" not in fact
        if fact["category"] == "kernel":
            assert "message" not in fact
        blobs.append(tool_get_fact(fact_id=fact["fact_id"], capture_id=ids["capture_a"]))
    for blob in blobs:
        assert FAKE_LABEL not in blob
        assert FAKE_FILENAME_A not in blob
        assert ARCH_BARE_ALICE not in blob
        assert ARCH_JANE not in blob
        assert ARCH_LABEL_UNDERSCORE not in blob
        assert "free_text_untrusted" not in blob


def test_free_text_opt_in_redacts_secrets_names_may_survive(ro_session, monkeypatch):
    """Flag=1 includes free text after PII/key + capture-identity scrub."""
    monkeypatch.setenv("PARSECAT_MCP_INCLUDE_FREE_TEXT", "1")
    session, ids, _ = ro_session
    facts_json = tool_get_verified_facts(capture_id=ids["capture_a"], limit=500)
    facts = json.loads(facts_json)["facts"]
    crash = [f for f in facts if f["category"] == "crash"][0]
    anr = [f for f in facts if f["category"] == "anr"][0]
    kernel = [f for f in facts if f["category"] == "kernel"][0]
    assert crash.get("free_text_untrusted") is True
    assert "message" in crash and "root_cause_message" in crash
    assert "reason" in anr
    assert "message" in kernel
    for text in (crash["message"], crash["root_cause_message"], anr["reason"], kernel["message"]):
        assert FAKE_PASSWORD not in text
        assert FAKE_SK not in text
        assert FAKE_EMAIL not in text
        assert FAKE_BEARER not in text
        # Capture-A identity tokens scrubbed in opt-in free text.
        assert FAKE_LABEL not in text
        assert FAKE_FILENAME_A not in text
        assert FAKE_SSID not in text
        assert FAKE_BSSID not in text
    # Residual risk (documented): other name seeds may survive.
    joined = " ".join([
        crash["message"], crash["root_cause_message"], anr["reason"], kernel["message"],
    ])
    assert ARCH_BARE_ALICE in joined or ARCH_JANE in joined
    one = tool_get_fact(fact_id=crash["fact_id"], capture_id=ids["capture_a"])
    assert "message" in json.loads(one)["fact"]

    monkeypatch.setenv("PARSECAT_MCP_INCLUDE_FREE_TEXT", "true")
    off = get_verified_facts(session, ids["capture_a"])
    off_crash = [f for f in off["facts"] if f["category"] == "crash"][0]
    assert "message" not in off_crash


def test_default_fact_limit_constant():
    assert DEFAULT_FACT_LIMIT == 100
    assert MAX_FACT_LIMIT == 500


def _cat_blobs(ids):
    list_json = tool_list_captures(offset=0, limit=100)
    facts_json = tool_get_verified_facts(capture_id=ids["capture_cat"], limit=500)
    facts = json.loads(facts_json)["facts"]
    blobs = [list_json, facts_json]
    for fact in facts:
        blobs.append(tool_get_fact(fact_id=fact["fact_id"], capture_id=ids["capture_cat"]))
    return blobs, facts


def test_cat_p1_identifier_canaries_withheld_default(ro_session):
    """Cat P1: poisoned thread/executable/other string IDs → null + withheld_fields."""
    session, ids, _ = ro_session
    blobs, facts = _cat_blobs(ids)
    assert facts
    for blob in blobs:
        for needle in CAT_CANARIES:
            assert needle not in blob, f"leaked {needle!r} in default output"
    # Crash with poisoned thread/classes withheld; clean crash keeps package.
    crashes = [f for f in facts if f["category"] == "crash"]
    poisoned = [c for c in crashes if c.get("package") is None or c.get("thread") is None]
    clean = [c for c in crashes if c.get("package") == "com.example.ok"]
    assert poisoned, "expected withheld crash fields"
    assert clean and clean[0]["thread"] == "main"
    assert any(
        any(w.get("field") == "thread" for w in (c.get("withheld_fields") or []))
        for c in crashes
    )
    natives = [f for f in facts if f["category"] == "native_crash"]
    assert natives and natives[0].get("executable") is None
    assert any(w.get("field") == "executable" for w in (natives[0].get("withheld_fields") or []))
    # Very long package emitted byte-for-byte (no 240 truncation).
    long_ones = [c for c in crashes if c.get("package") == VERY_LONG_PACKAGE]
    assert long_ones, "very long package must survive verbatim"
    assert len(long_ones[0]["package"]) == len(VERY_LONG_PACKAGE)
    assert len(VERY_LONG_PACKAGE) > 240


def test_cat_p1_free_text_opt_in_scrubs_ssid_serial_ip_filename(ro_session, monkeypatch):
    """Cat P1 flag-on: SSID/serial/IP/filename scrubbed in free text."""
    monkeypatch.setenv("PARSECAT_MCP_INCLUDE_FREE_TEXT", "1")
    session, ids, _ = ro_session
    facts_json = tool_get_verified_facts(capture_id=ids["capture_cat"], limit=500)
    facts = json.loads(facts_json)["facts"]
    texts = []
    for f in facts:
        for k in ("message", "root_cause_message", "reason"):
            if isinstance(f.get(k), str):
                texts.append(f[k])
        blobs = [facts_json, tool_get_fact(fact_id=f["fact_id"], capture_id=ids["capture_cat"])]
        for blob in blobs:
            assert CAT_SSID not in blob
            assert CAT_SERIAL not in blob
            assert CAT_IP not in blob
            assert CAT_FILE not in blob
            assert CAT_MAC not in blob
            assert CAT_EMAIL not in blob
    assert texts, "expected opt-in free text"
    joined = " ".join(texts)
    assert CAT_SSID not in joined
    assert CAT_SERIAL not in joined
    assert CAT_IP not in joined
    assert CAT_FILE not in joined
    assert "[redacted-ip]" in joined or "ip=" not in joined.lower()


def test_cat_p2_identifier_never_truncated(ro_session):
    session, ids, _ = ro_session
    facts_json = tool_get_verified_facts(capture_id=ids["capture_cat"], limit=500)
    assert VERY_LONG_PACKAGE in facts_json
    assert len(VERY_LONG_PACKAGE) <= MAX_IDENTIFIER_CHARS
    # Oversize identifier → withheld, not truncated.
    from app.services.mcp_readonly import _stamp, CaptureIdentity
    huge = "com.example." + ("z" * (MAX_IDENTIFIER_CHARS + 50))
    stamped = _stamp("crash", 1, {
        "timestamp": "08-19 12:00:00.000",
        "package": huge,
        "thread": "main",
        "exception_class": "RuntimeException",
        "confidence": "LOW",
    }, identity=CaptureIdentity())
    assert stamped.get("package") is None
    assert any(w["field"] == "package" and w["reason"] == "too_long"
               for w in stamped.get("withheld_fields") or [])
    assert huge not in json.dumps(stamped)


def test_cat_p2_malformed_args_no_echo():
    """SDK call_tool must not echo pydantic input_value / raw submitted args."""
    async def _run():
        with pytest.raises(ToolError) as ei:
            await mcp.call_tool(
                "get_verified_facts",
                {"capture_id": "not-an-int", "limit": "nope"},
            )
        return ei.value

    err = asyncio.run(_run())
    msg = str(err)
    assert msg.startswith("invalid arguments:")
    assert "capture_id" in msg and "limit" in msg
    assert "not-an-int" not in msg
    assert "nope" not in msg
    assert "input_value" not in msg
    assert "ValidationError" not in msg


def test_cat_p3_selinux_permissions_list(ro_session):
    session, ids, _ = ro_session
    facts_json = tool_get_verified_facts(capture_id=ids["capture_cat"], limit=500)
    facts = json.loads(facts_json)["facts"]
    sel = [f for f in facts if f["category"] == "selinux"]
    assert sel
    perms = sel[0]["permissions"]
    assert isinstance(perms, list)
    assert perms == ["read", "write", "getattr"]
    # Serialized JSON is a list, not a joined string.
    assert '"permissions": ["read", "write", "getattr"]' in facts_json or (
        '"permissions":["read","write","getattr"]' in facts_json
    )
    one = tool_get_fact(fact_id=sel[0]["fact_id"], capture_id=ids["capture_cat"])
    assert isinstance(json.loads(one)["fact"]["permissions"], list)

