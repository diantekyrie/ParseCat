"""#118: pcap evidence must enter the diagnose bundle for Wi-Fi/disconnect
questions, not only pairing-triggered ones.

Synthetic fixtures only. Asserts on build_diagnosis_bundle keys, not LLM prose.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.models.db_models import (
    Capture,
    Device,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
)
from app.services.reasoning import build_diagnosis_bundle


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _device(session, label="synthetic-pcap-gate-phone"):
    device = Device(label=label)
    session.add(device)
    session.commit()
    session.refresh(device)
    return device


def _capture(session, device, filename="synthetic-wifi-deauth.pcap"):
    cap = Capture(device_id=device.id, original_filename=filename)
    session.add(cap)
    session.commit()
    session.refresh(cap)
    return cap


def _seed_pcap_rows(session, capture_id: int):
    session.add(PacketCaptureSummaryRow(
        capture_id=capture_id,
        format="pcap",
        linktype=127,
        linktype_name="IEEE802_11_RADIO",
        total_packets=3,
        captured_bytes=300,
        original_bytes=300,
        first_timestamp="1.0",
        last_timestamp="3.0",
        truncated_packets=0,
        malformed_packets=0,
    ))
    session.add(PacketAnalysisRow(
        capture_id=capture_id,
        backend="tshark",
        packets_analyzed=3,
        link_layer="802.11",
        retry_count=0,
        retry_rate_pct=0.0,
        rssi_min_dbm=-70,
        rssi_max_dbm=-50,
        rssi_avg_dbm=-60.0,
        note="synthetic tshark analysis for gate test",
        frame_type_breakdown_json=json.dumps(
            [{"label": "Management (subtype 12)", "count": 1}]
        ),
        identity_signals_json=json.dumps([]),
        anomalies_json=json.dumps([{
            "timestamp": "2.0",
            "kind": "deauthentication",
            "detail": "Deauthentication frame, reason code 3 (Deauthenticated: station leaving)",
            "mac_or_ip": "aa:bb:cc:dd:ee:ff",
        }]),
    ))
    session.commit()


def test_wifi_disconnect_question_includes_pcap_evidence(session):
    """Both sides of the gate — INCLUDE: Wi-Fi/disconnect wording."""
    device = _device(session)
    cap = _capture(session, device)
    _seed_pcap_rows(session, cap.id)

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Why did Wi-Fi disconnect? What was the deauth reason code?",
    )
    assert "packet_capture_summary" in bundle
    assert "packet_analysis" in bundle
    assert bundle["packet_capture_summary"][0]["total_packets"] == 3
    anomalies = bundle["packet_analysis"][0]["anomalies"]
    assert anomalies
    assert "reason code 3" in anomalies[0]["detail"]
    # mac_or_ip stripped on LLM-bound path
    assert "mac_or_ip" not in anomalies[0]


def test_battery_question_excludes_pcap_evidence(session):
    """Both sides of the gate — EXCLUDE: unrelated battery question."""
    device = _device(session)
    cap = _capture(session, device)
    _seed_pcap_rows(session, cap.id)

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Why is the battery draining so fast?",
    )
    assert "packet_capture_summary" not in bundle
    assert "packet_analysis" not in bundle


def test_pairing_question_still_includes_pcap_evidence(session):
    """Pairing trigger must keep including pcap (want_pairing side of OR)."""
    device = _device(session)
    cap = _capture(session, device)
    _seed_pcap_rows(session, cap.id)

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Why did Bluetooth pairing fail?",
    )
    assert "packet_capture_summary" in bundle
    assert "packet_analysis" in bundle


def test_include_all_evidence_still_includes_pcap(session):
    """include_all_evidence (auto-scan) must still gather pcap categories."""
    device = _device(session)
    cap = _capture(session, device)
    _seed_pcap_rows(session, cap.id)

    bundle = build_diagnosis_bundle(
        session, cap.id, device.label,
        "Full automatic scan: what problems are present on this device?",
        include_all_evidence=True,
    )
    assert "packet_capture_summary" in bundle
    assert "packet_analysis" in bundle
