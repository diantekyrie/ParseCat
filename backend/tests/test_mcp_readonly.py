"""Read-only MCP server privacy/scope/budget tests.

Synthetic fixtures only — no real captures / PII / live keys.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError
from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import (
    Capture,
    CompanionDeviceAssociationRow,
    CrashEventRow,
    Device,
    WifiEventRow,
)
from app.mcp_server import (
    READONLY_TOOL_NAMES,
    WRITEISH_TOOL_NAME_FRAGMENTS,
    get_fact as tool_get_fact,
    get_verified_facts as tool_get_verified_facts,
    list_captures as tool_list_captures,
    mcp,
)
from app.services.mcp_readonly import (
    DEFAULT_FACT_LIMIT,
    FACT_META_KEYS,
    LIST_CAPTURE_ITEM_KEYS,
    MAX_FACT_LIMIT,
    MAX_OUTPUT_BYTES,
    MAX_STRING_CHARS,
    MCP_REDACT_KEYS,
    CaptureNotFoundError,
    FactNotFoundError,
    assert_engine_is_readonly,
    get_fact,
    get_verified_facts,
    list_captures,
    open_readonly_engine,
    project_fact,
    scrub_text,
)


# Synthetic seeds — never real credentials or personal data.
FAKE_SSID = "ssid-mcp-test"
FAKE_BSSID = "aa:bb:cc:dd:ee:11"
FAKE_MAC = "aa:bb:cc:dd:ee:22"
FAKE_MAC_IN_TEXT = "aa:bb:cc:dd:ee:33"
FAKE_CDM_NAME = "Fake private watch"
FAKE_EMAIL = "alice.mcp@example.com"
FAKE_PHONE = "+1-415-555-0199"
FAKE_LABEL = "mcp-synth-phone-label"
FAKE_FILENAME_A = "mcp-synth-report-A.zip"
FAKE_FILENAME_B = "mcp-synth-report-B.zip"
# Key-shaped tokens patterned like #102 coverage (synthetic, not real keys).
FAKE_SK = "sk-or-v1-mcpSYNTHETIC00000000000000000001"
FAKE_AIZA = "AIzaSyMcpSyntheticTestKey00000000001"
FAKE_GSK = "gsk_mcpSyntheticTestKey0000000000001"


@pytest.fixture
def writable_db(tmp_path: Path):
    """Writable SQLite with two sibling captures + archived device."""
    db_path = tmp_path / "parsecat.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        active = Device(label=FAKE_LABEL, archived=False)
        archived = Device(label="mcp-archived-label", archived=True)
        session.add(active)
        session.add(archived)
        session.commit()
        session.refresh(active)
        session.refresh(archived)

        cap_a = Capture(device_id=active.id, original_filename=FAKE_FILENAME_A)
        cap_b = Capture(device_id=active.id, original_filename=FAKE_FILENAME_B)
        hidden = Capture(device_id=archived.id, original_filename="mcp-hidden.zip")
        session.add(cap_a)
        session.add(cap_b)
        session.add(hidden)
        session.commit()
        session.refresh(cap_a)
        session.refresh(cap_b)
        session.refresh(hidden)

        # Capture A: wifi + CDM + crash with embedded email/key/mac/phone.
        session.add(WifiEventRow(
            capture_id=cap_a.id,
            timestamp="08-19 12:00:00.000",
            kind="disconnection",
            ssid=FAKE_SSID,
            bssid=FAKE_BSSID,
            reason_code=3,
            reason_name="Deauthenticated because sending STA is leaving",
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
            display_name=FAKE_CDM_NAME,
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
        crash_msg = (
            f"boom contact {FAKE_EMAIL} phone {FAKE_PHONE} "
            f"key {FAKE_SK} also {FAKE_AIZA} and {FAKE_GSK} "
            f"mac {FAKE_MAC_IN_TEXT}"
        )
        session.add(CrashEventRow(
            capture_id=cap_a.id,
            timestamp="08-19 12:01:00.000",
            thread="main",
            package="com.example.app",
            pid=42,
            exception_class="RuntimeException",
            message=crash_msg,
            root_cause_class=None,
            root_cause_message=None,
            root_cause_frame=None,
            source_section="system_log",
            source_line_start=100,
            source_line_end=120,
        ))
        # Capture B: distinct wifi event (sibling scope probe).
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
        session.commit()
        ids = {
            "db_path": db_path,
            "capture_a": cap_a.id,
            "capture_b": cap_b.id,
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


def _assert_no_leaks(blob: str):
    lowered = blob.lower()
    for needle in (
        FAKE_SSID, FAKE_BSSID, FAKE_MAC, FAKE_MAC_IN_TEXT,
        FAKE_CDM_NAME, FAKE_EMAIL, FAKE_PHONE, FAKE_LABEL,
        FAKE_FILENAME_A, FAKE_FILENAME_B,
        FAKE_SK, FAKE_AIZA, FAKE_GSK,
        "ssid-sibling-only", "aa:bb:cc:dd:ee:99",
    ):
        assert needle.lower() not in lowered, f"leaked {needle!r}"


def _untrusted_texts(fact: dict) -> str:
    block = fact.get("untrusted_log_text") or {}
    parts = []
    for key in ("summary", "detail"):
        node = block.get(key) or {}
        if isinstance(node, dict) and node.get("text"):
            parts.append(node["text"])
    return "\n".join(parts)


# --- unit helpers -----------------------------------------------------------

def test_scrub_text_redacts_pii_keys_and_macs():
    raw = (
        f"email {FAKE_EMAIL} phone {FAKE_PHONE} "
        f"{FAKE_SK} {FAKE_AIZA} {FAKE_GSK} mac {FAKE_MAC_IN_TEXT}"
    )
    out = scrub_text(raw)
    assert out is not None
    _assert_no_leaks(out)
    assert "[redacted-email]" in out or "example.com" not in out
    assert "[redacted]" in out  # key-like
    assert "[redacted-mac]" in out


def test_project_fact_fail_closed_drops_unknown_and_sibling():
    sibling = {
        "fact_id": "vf_aaaaaaaaaaaaaaaa",
        "category": "wifi",
        "summary": "Wi-Fi disconnection (x)",
        "detail": "locally generated",
        "confidence": "LOW",
        "capture_id": 99,
        "device_label": FAKE_LABEL,
        "original_filename": FAKE_FILENAME_B,
        "ssid": FAKE_SSID,
        "display_name": FAKE_CDM_NAME,
    }
    assert project_fact(sibling, capture_id=1) is None

    ok = {
        "fact_id": "vf_bbbbbbbbbbbbbbbb",
        "category": "pairing",
        "summary": f"CDM association present: {FAKE_CDM_NAME}",
        "detail": f"connected=True, package=com.example mac {FAKE_MAC}",
        "confidence": "LOW",
        "capture_id": 1,
        "extra_evil": {"mac_address": FAKE_MAC},
        "parse_warnings": "secret",
    }
    projected = project_fact(ok, capture_id=1)
    assert projected is not None
    assert set(projected.keys()) <= FACT_META_KEYS
    assert "extra_evil" not in projected
    assert "parse_warnings" not in projected
    assert "device_label" not in projected
    blob = json.dumps(projected)
    assert FAKE_CDM_NAME not in blob
    assert FAKE_MAC not in blob
    assert projected["untrusted_log_text"]["summary"]["untrusted"] is True
    assert projected["untrusted_log_text"]["summary"]["kind"] == "device_log"


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
        with pytest.raises(OperationalError):
            conn.exec_driver_sql("INSERT INTO capture (id) VALUES (999999)")
            conn.commit()
        with pytest.raises(OperationalError):
            conn.exec_driver_sql("DELETE FROM capture")
            conn.commit()


def test_missing_db_does_not_create(tmp_path):
    missing = tmp_path / "nope.db"
    with pytest.raises(FileNotFoundError):
        open_readonly_engine(missing)
    assert not missing.exists()


# --- list_captures ----------------------------------------------------------

def test_list_captures_hides_archived_and_omits_label_filename(ro_session):
    session, ids, _ = ro_session
    payload = list_captures(session)
    listed = {c["id"] for c in payload["captures"]}
    assert ids["capture_a"] in listed
    assert ids["capture_b"] in listed
    assert ids["hidden"] not in listed
    for cap in payload["captures"]:
        assert set(cap.keys()) <= LIST_CAPTURE_ITEM_KEYS
        assert "label" not in cap
        assert "original_filename" not in cap
    blob = json.dumps(payload)
    _assert_no_leaks(blob)
    assert "untrusted_data_notice" in payload


def test_list_captures_pagination(ro_session):
    session, ids, _ = ro_session
    page1 = list_captures(session, offset=0, limit=1)
    assert page1["returned"] == 1
    assert page1["total"] >= 2
    assert page1["truncated"] is True
    assert page1["next_offset"] == 1
    page2 = list_captures(session, offset=1, limit=1)
    assert page2["captures"][0]["id"] != page1["captures"][0]["id"]


# --- capture scope (Arch) ---------------------------------------------------

def test_get_verified_facts_excludes_sibling_capture(ro_session):
    session, ids, _ = ro_session
    payload = get_verified_facts(session, ids["capture_a"])
    caps = {f.get("capture_id") for f in payload["facts"]}
    assert caps == {ids["capture_a"]}
    blob = json.dumps(payload)
    assert "ssid-sibling-only" not in blob
    assert "inactivity" not in blob.lower() or "disconnection" in blob.lower()
    # Sibling-only reason text from B must not appear.
    assert "Disassociated due to inactivity" not in blob


def test_get_fact_sibling_id_with_capture_a_not_found(ro_session):
    session, ids, _ = ro_session
    b_payload = get_verified_facts(session, ids["capture_b"])
    assert b_payload["facts"], "need B facts"
    b_fact_id = b_payload["facts"][0]["fact_id"]
    with pytest.raises(FactNotFoundError):
        get_fact(session, b_fact_id, capture_id=ids["capture_a"])
    # Same fact resolves when scoped to B.
    found = get_fact(session, b_fact_id, capture_id=ids["capture_b"])
    assert found["fact"]["capture_id"] == ids["capture_b"]


# --- privacy on all three tools (FE) ----------------------------------------

def test_get_verified_facts_privacy_and_allowlist(ro_session):
    session, ids, _ = ro_session
    payload = get_verified_facts(session, ids["capture_a"])
    assert payload["total"] >= 1
    blob = json.dumps(payload)
    _assert_no_leaks(blob)
    for fact in payload["facts"]:
        assert set(fact.keys()) <= FACT_META_KEYS
        assert "device_label" not in fact
        assert "original_filename" not in fact
        assert "ssid" not in fact
        assert "display_name" not in fact
        ult = fact.get("untrusted_log_text")
        if ult:
            for node in ult.values():
                assert node.get("untrusted") is True
                assert node.get("kind") == "device_log"
                assert len(node.get("text") or "") <= MAX_STRING_CHARS + 3
    wifi = [f for f in payload["facts"] if f.get("category") == "wifi"]
    assert wifi, "approved wifi diagnostic fact must survive"
    pairing = [f for f in payload["facts"] if f.get("category") == "pairing"]
    assert pairing, "approved pairing fact must survive without CDM name"
    for f in pairing:
        text = _untrusted_texts(f)
        assert FAKE_CDM_NAME not in text
        assert "CDM association present" in text


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


def test_serialized_tool_outputs_privacy(ro_session, monkeypatch):
    """Positive/negative checks on the actual MCP tool JSON strings."""
    session, ids, _ = ro_session
    # Tools open their own session via PARSECAT_DB_PATH (monkeypatched fixture).
    list_json = tool_list_captures(offset=0, limit=10)
    facts_json = tool_get_verified_facts(capture_id=ids["capture_a"], limit=50)
    facts_obj = json.loads(facts_json)
    assert facts_obj["facts"], "need a fact for get_fact"
    fact_id = facts_obj["facts"][0]["fact_id"]
    one_json = tool_get_fact(fact_id=fact_id, capture_id=ids["capture_a"])

    for blob in (list_json, facts_json, one_json):
        assert isinstance(blob, str)
        _assert_no_leaks(blob)
        parsed = json.loads(blob)
        assert "untrusted_data_notice" in parsed

    # Positive: approved fields remain.
    list_obj = json.loads(list_json)
    assert any(c["id"] == ids["capture_a"] for c in list_obj["captures"])
    assert any(f["category"] == "wifi" for f in facts_obj["facts"])
    one_obj = json.loads(one_json)
    assert one_obj["fact"]["fact_id"] == fact_id

    # Sibling fact must not resolve through capture A tool path.
    b_json = tool_get_verified_facts(capture_id=ids["capture_b"], limit=50)
    b_fact_id = json.loads(b_json)["facts"][0]["fact_id"]
    with pytest.raises(Exception):
        tool_get_fact(fact_id=b_fact_id, capture_id=ids["capture_a"])


def test_byte_budget_enforced(ro_session, monkeypatch):
    session, ids, _ = ro_session
    # Shrink budget so a normal payload must truncate.
    import app.services.mcp_readonly as mod
    monkeypatch.setattr(mod, "MAX_OUTPUT_BYTES", 800)
    payload = get_verified_facts(session, ids["capture_a"], limit=500)
    blob = json.dumps(payload, default=str, ensure_ascii=True)
    assert len(blob.encode("utf-8")) <= 800 or payload.get("byte_truncated") is True
    # Restore invariant: even if truncated, no leaks.
    _assert_no_leaks(blob)


def test_mcp_server_tool_list_has_no_write_tools():
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert names == set(READONLY_TOOL_NAMES)
    for name in names:
        lowered = name.lower()
        for frag in WRITEISH_TOOL_NAME_FRAGMENTS:
            assert frag not in lowered, f"tool {name!r} looks write-capable"


def test_default_fact_limit_constant():
    assert DEFAULT_FACT_LIMIT == 100
    assert MAX_FACT_LIMIT == 500
    assert MAX_OUTPUT_BYTES >= 1024
