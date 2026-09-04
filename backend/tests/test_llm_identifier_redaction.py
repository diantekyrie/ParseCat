"""PC-narration-008/009: strip SSID/BSSID/MAC from Diagnose/Scan LLM bundles.

Identifiers may remain in local SQLite for UI. Assert on build_diagnosis_bundle
(the LLM-bound path), not free prose. Fake values only — no real MACs/SSIDs.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import (
    Capture,
    CdmPairingEventRow,
    CompanionDeviceAssociationRow,
    Device,
    WifiEventRow,
)
from app.services.reasoning import (
    LLM_EVIDENCE_REDACT_KEYS,
    build_diagnosis_bundle,
)


FAKE_SSID = "ssid-test"
FAKE_BSSID = "aa:bb:cc:dd:ee:01"
FAKE_MAC = "aa:bb:cc:dd:ee:02"


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _device(session, label="synthetic-redact-phone"):
    device = Device(label=label)
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def _capture(session, device, filename="synthetic-wifi-pairing.zip"):
    cap = Capture(device_id=device.id, original_filename=filename)
    session.add(cap)
    session.commit()
    session.refresh(cap)
    return cap


def _assert_no_identifier_keys(obj, path="$"):
    """Recursively assert redacted keys are absent from LLM-bound JSON."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            assert key not in LLM_EVIDENCE_REDACT_KEYS, f"{path}.{key} present"
            _assert_no_identifier_keys(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _assert_no_identifier_keys(item, f"{path}[{i}]")


def _assert_fake_values_absent(payload: str):
    lowered = payload.lower()
    for fake in (FAKE_SSID, FAKE_BSSID, FAKE_MAC):
        assert fake.lower() not in lowered, f"leaked {fake!r} into LLM payload"


def test_llm_evidence_redact_keys_cover_network_identifiers():
    """Mirror test_device_context_allowlist_excludes_serial — constant gate."""
    assert "ssid" in LLM_EVIDENCE_REDACT_KEYS
    assert "bssid" in LLM_EVIDENCE_REDACT_KEYS
    assert "mac_address" in LLM_EVIDENCE_REDACT_KEYS
    assert "mac_or_ip" in LLM_EVIDENCE_REDACT_KEYS


def test_pc_narration_008_wifi_identifiers_absent_from_llm_bundle(session):
    """Diagnose LLM-bound payload with Wi-Fi disconnection evidence — no ssid/bssid/mac."""
    device = _device(session)
    cap = _capture(session, device)
    session.add(WifiEventRow(
        capture_id=cap.id,
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
    session.commit()

    # Local DB still has identifiers for UI / summary paths.
    db_row = session.exec(select(WifiEventRow).where(WifiEventRow.capture_id == cap.id)).one()
    assert db_row.ssid == FAKE_SSID
    assert db_row.bssid == FAKE_BSSID

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Why did Wi-Fi disconnect?",
    )
    wifi = bundle.get("device_wide_wifi_evidence")
    assert wifi is not None
    assert wifi["disconnections"], "expected disconnection evidence in bundle"
    for row in wifi["disconnections"]:
        assert "ssid" not in row
        assert "bssid" not in row
        assert "mac_address" not in row
        assert "reason_code" in row
        assert "reason_name" in row

    payload = json.dumps(bundle, default=str)
    _assert_no_identifier_keys(bundle)
    _assert_fake_values_absent(payload)


def test_pc_narration_009_pairing_mac_absent_from_llm_bundle(session):
    """Pairing/companion evidence — mac_address (and BSSID-equivalents) absent from LLM payload."""
    device = _device(session, label="synthetic-pairing-phone")
    cap = _capture(session, device, filename="synthetic-pairing.zip")
    session.add(CdmPairingEventRow(
        capture_id=cap.id,
        timestamp="08-19 12:05:00.000",
        level="I",
        tag="CDM_CompanionDeviceActivity",
        kind="association_approved",
        mac_address=FAKE_MAC,
        display_name="Test Watch",
        package_name="com.example.companion",
        association_id=1,
        detail="onAssociationApproved() synthetic",
        source_section="system_log",
        source_line_start=20,
        source_line_end=20,
    ))
    session.add(CompanionDeviceAssociationRow(
        capture_id=cap.id,
        association_id=1,
        mac_address=FAKE_MAC,
        display_name="Test Watch",
        package_name="com.example.companion",
        device_profile="WATCH",
        self_managed=False,
        revoked=False,
        pending=False,
        trusted=True,
        time_approved="08-19 12:05:00.000",
        last_time_connected="08-19 12:06:00.000",
        currently_connected=True,
        source_section="companiondevice",
        source_line_start=1,
        source_line_end=5,
    ))
    session.commit()

    db_event = session.exec(
        select(CdmPairingEventRow).where(CdmPairingEventRow.capture_id == cap.id)
    ).one()
    db_assoc = session.exec(
        select(CompanionDeviceAssociationRow).where(
            CompanionDeviceAssociationRow.capture_id == cap.id
        )
    ).one()
    assert db_event.mac_address == FAKE_MAC
    assert db_assoc.mac_address == FAKE_MAC

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Is the companion device paired over Bluetooth?",
    )
    pairing = bundle.get("device_wide_pairing_evidence")
    assert pairing is not None
    assert pairing["events"], "expected pairing events in bundle"
    for row in pairing["events"]:
        assert "mac_address" not in row
        assert "ssid" not in row
        assert "bssid" not in row
        assert row.get("display_name") == "Test Watch"
        assert row.get("package_name") == "com.example.companion"

    assocs = pairing.get("current_associations") or []
    assert assocs, "expected current_associations in bundle"
    for row in assocs:
        assert "mac_address" not in row
        assert "ssid" not in row
        assert "bssid" not in row
        assert row.get("currently_connected") is True

    payload = json.dumps(bundle, default=str)
    _assert_no_identifier_keys(bundle)
    _assert_fake_values_absent(payload)
