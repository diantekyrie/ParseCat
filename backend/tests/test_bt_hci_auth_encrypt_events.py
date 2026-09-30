"""Round 2 Msg5: BT HCI auth / encryption / link-key / pairing decode +
synthetic CI fixtures for PC-bt-hci-001..004 (issue #65).

Synthetic btsnoop bytes only — no real captures/PII. Link-key material in
fixtures is zeros; BD_ADDRs are synthetic (AA:BB:CC:DD:EE:FF). Parser must
not surface key bytes or addresses on decoded facts.
"""
from __future__ import annotations

import struct

import pytest

from app.parsers.bt_hci import (
    ENCRYPTION_ENABLED_NAMES,
    LINK_KEY_TYPE_NAMES,
    build_handle_failure_sequences,
    parse_bt_hci_log,
    _encryption_enabled_name,
    _link_key_type_name,
    _status_name,
)

BTSNOOP_EPOCH = 0x00DCDDB30F2F8000
SYNTH_BD_ADDR = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])  # AA:BB:CC:DD:EE:FF LE
ZERO_LINK_KEY = bytes(16)


def _hci_event(event_code: int, params: bytes) -> bytes:
    return bytes([0x04, event_code, len(params)]) + params


def _btsnoop(records: list[bytes], *, base_ts: int = BTSNOOP_EPOCH) -> bytes:
    header = b"btsnoop\x00" + struct.pack(">II", 1, 1002)
    out = bytearray(header)
    for i, payload in enumerate(records):
        ts = base_ts + i * 1_000_000  # 1s apart
        out += struct.pack(">IIIIQ", len(payload), len(payload), 0, 0, ts)
        out += payload
    return bytes(out)


def _u16(n: int) -> bytes:
    return struct.pack("<H", n)


# ---- lookup invent-nothing -------------------------------------------------

def test_encryption_enabled_known_and_unknown():
    assert _encryption_enabled_name(0x00) == ENCRYPTION_ENABLED_NAMES[0x00]
    assert _encryption_enabled_name(0x01) == ENCRYPTION_ENABLED_NAMES[0x01]
    assert _encryption_enabled_name(0x02) == ENCRYPTION_ENABLED_NAMES[0x02]
    assert 0x03 not in ENCRYPTION_ENABLED_NAMES
    assert _encryption_enabled_name(0x03) == "Unknown (0x03)"


def test_link_key_type_known_and_unknown():
    assert _link_key_type_name(0x05) == LINK_KEY_TYPE_NAMES[0x05]
    assert 0x09 not in LINK_KEY_TYPE_NAMES
    assert _link_key_type_name(0x09) == "Unknown (0x09)"


# ---- PC-bt-hci-001..004 (#65) ---------------------------------------------

def test_pc_bt_hci_001_authentication_failure():
    """PC-bt-hci-001: auth complete with status 0x05 Authentication Failure."""
    handle = 0x000B
    pkt = _hci_event(0x06, bytes([0x05]) + _u16(handle))
    summary = parse_bt_hci_log(_btsnoop([pkt]))
    assert summary is not None
    assert len(summary.events) == 1
    e = summary.events[0]
    assert e.kind == "authentication_complete"
    assert e.status_code == 0x05
    assert e.status_name == "Authentication Failure"
    assert e.handle == handle
    assert e.severity == "critical"
    assert e.confidence == "HIGH"
    assert e.source_ref is not None
    assert e.source_ref.section == "bt_hci"
    assert e.source_ref.line_start == 1


def test_pc_bt_hci_002_disconnect_connection_timeout():
    """PC-bt-hci-002: disconnection reason 0x08 Connection Timeout."""
    handle = 0x000C
    pkt = _hci_event(0x05, bytes([0x00]) + _u16(handle) + bytes([0x08]))
    summary = parse_bt_hci_log(_btsnoop([pkt]))
    assert summary is not None
    e = summary.events[0]
    assert e.kind == "disconnection_complete"
    assert e.status_code == 0x00
    assert e.reason_code == 0x08
    assert e.reason_name == "Connection Timeout"
    assert e.severity == "warning"
    assert e.confidence == "HIGH"


def test_pc_bt_hci_003_le_connection_failed_to_establish():
    """PC-bt-hci-003: LE connection complete with non-success status 0x3E."""
    handle = 0x0010
    # LE Meta: subevent 0x01 Connection Complete; status + handle + pad
    params = bytes([0x01, 0x3E]) + _u16(handle) + bytes(8)
    pkt = _hci_event(0x3E, params)
    summary = parse_bt_hci_log(_btsnoop([pkt]))
    assert summary is not None
    e = summary.events[0]
    assert e.kind == "le_connection_complete"
    assert e.status_code == 0x3E
    assert e.status_name == "Connection Failed to be Established"
    assert e.handle == handle
    assert e.severity == "warning"
    assert e.confidence == "HIGH"


def test_pc_bt_hci_004_unknown_status_stays_unknown():
    """PC-bt-hci-004: unknown status → Unknown (0xNN) via _status_name."""
    assert _status_name(0xFE) == "Unknown (0xFE)"
    handle = 0x0001
    pkt = _hci_event(0x06, bytes([0xFE]) + _u16(handle))
    summary = parse_bt_hci_log(_btsnoop([pkt]))
    e = summary.events[0]
    assert e.status_name == "Unknown (0xFE)"
    assert e.severity == "critical"  # auth path with non-zero status
    assert e.confidence == "HIGH"


# ---- Msg5 new event kinds -------------------------------------------------

def test_encryption_change_on():
    handle = 0x0020
    pkt = _hci_event(0x08, bytes([0x00]) + _u16(handle) + bytes([0x01]))
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "encryption_change"
    assert e.status_code == 0x00
    assert e.encryption_enabled == 0x01
    assert e.reason_name == ENCRYPTION_ENABLED_NAMES[0x01]
    assert e.severity == "info"
    assert e.confidence == "HIGH"


def test_encryption_change_failure():
    handle = 0x0021
    pkt = _hci_event(0x08, bytes([0x25]) + _u16(handle) + bytes([0x00]))
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "encryption_change"
    assert e.status_name == "Encryption Mode Not Acceptable"
    assert e.severity == "critical"


def test_link_key_request_no_address_stored():
    pkt = _hci_event(0x17, SYNTH_BD_ADDR)
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "link_key_request"
    assert e.status_code is None
    assert e.handle is None
    # Ensure fixture address bytes never appear on the fact stringification.
    dumped = repr(e)
    assert "ff:ee:dd" not in dumped.lower()
    assert SYNTH_BD_ADDR.hex() not in dumped.lower()


def test_link_key_notification_stores_type_not_key():
    params = SYNTH_BD_ADDR + ZERO_LINK_KEY + bytes([0x05])
    assert len(params) == 23
    pkt = _hci_event(0x18, params)
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "link_key_notification"
    assert e.key_type == 0x05
    assert e.reason_name == LINK_KEY_TYPE_NAMES[0x05]
    dumped = repr(e)
    assert ZERO_LINK_KEY.hex() not in dumped
    assert SYNTH_BD_ADDR.hex() not in dumped.lower()


def test_simple_pairing_complete_failure():
    pkt = _hci_event(0x36, bytes([0x18]) + SYNTH_BD_ADDR)
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "simple_pairing_complete"
    assert e.status_code == 0x18
    assert e.status_name == "Pairing Not Allowed"
    assert e.severity == "critical"


def test_change_connection_link_key_complete():
    handle = 0x0030
    pkt = _hci_event(0x09, bytes([0x00]) + _u16(handle))
    e = parse_bt_hci_log(_btsnoop([pkt])).events[0]
    assert e.kind == "change_connection_link_key_complete"
    assert e.handle == handle
    assert e.status_name == "Success"


# ---- per-handle failure sequence -----------------------------------------

def test_handle_failure_sequence_auth_then_disconnect():
    handle = 0x0042
    records = [
        _hci_event(0x03, bytes([0x00]) + _u16(handle) + SYNTH_BD_ADDR + bytes([0x01, 0x00])),
        _hci_event(0x06, bytes([0x05]) + _u16(handle)),  # auth fail
        _hci_event(0x05, bytes([0x00]) + _u16(handle) + bytes([0x05])),  # disc auth failure
    ]
    summary = parse_bt_hci_log(_btsnoop(records))
    assert summary is not None
    seqs = summary.handle_failure_sequences
    assert len(seqs) == 1
    seq = seqs[0]
    assert seq.handle == handle
    assert seq.disconnect_reason_code == 0x05
    assert seq.disconnect_reason_name == "Authentication Failure"
    kinds = [e.kind for e in seq.events]
    assert kinds[0] == "connection_complete"
    assert kinds[1] == "authentication_complete"
    assert kinds[-1] == "disconnection_complete"
    # SourceRef record indices are 1-based and stable across the sequence.
    assert [e.source_ref.line_start for e in seq.events] == [1, 2, 3]


def test_handle_sequence_without_failure_omitted():
    handle = 0x0043
    records = [
        _hci_event(0x03, bytes([0x00]) + _u16(handle) + SYNTH_BD_ADDR + bytes([0x01, 0x00])),
        _hci_event(0x06, bytes([0x00]) + _u16(handle)),  # auth success
        _hci_event(0x08, bytes([0x00]) + _u16(handle) + bytes([0x01])),  # encrypt on
        # remote user term — reason 0x13 is non-zero, so this *is* a failure
        # sequence by reason. Use local host with reason Success? Disconnect
        # reason 0x16 is still non-zero. For a clean happy-path we need no
        # disconnect, or only success-status events without disconnect.
    ]
    summary = parse_bt_hci_log(_btsnoop(records))
    # No disconnection_complete trailer → no failure sequence.
    assert summary.handle_failure_sequences == []
    assert build_handle_failure_sequences(summary.events) == []


def test_sourceref_and_confidence_on_all_decoded_kinds():
    records = [
        _hci_event(0x06, bytes([0x00]) + _u16(1)),
        _hci_event(0x08, bytes([0x00]) + _u16(1) + bytes([0x02])),
        _hci_event(0x17, SYNTH_BD_ADDR),
        _hci_event(0x18, SYNTH_BD_ADDR + ZERO_LINK_KEY + bytes([0x07])),
        _hci_event(0x36, bytes([0x00]) + SYNTH_BD_ADDR),
        _hci_event(0x09, bytes([0x00]) + _u16(1)),
    ]
    events = parse_bt_hci_log(_btsnoop(records)).events
    assert len(events) == 6
    for i, e in enumerate(events, start=1):
        assert e.source_ref.section == "bt_hci"
        assert e.source_ref.line_start == i
        assert e.confidence == "HIGH"
        assert e.severity in ("info", "warning", "critical")
