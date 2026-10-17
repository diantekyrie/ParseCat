"""Regression tests for BT HCI status and Wi-Fi 802.11 reason lookup tables.

Synthetic only — no real captures/PII. Covers Round 2 Msg4 Eggbot gaps for
HCI_STATUS_NAMES (0x18-0x19, 0x1B-0x21, 0x23-0x24) and REASON_CODE_NAMES
(10-14, 21-22, 24-33). Unknown / unused codes must stay on the existing
fallback strings, never invent names.
"""
from __future__ import annotations

import pytest

from app.parsers.bt_hci import HCI_STATUS_NAMES, _status_name
from app.parsers.wifi import REASON_CODE_NAMES, _reason_name


# Bluetooth Core Spec Part F controller error codes (Eggbot gap fill).
HCI_EGGBOT_FILLED = {
    0x18: "Pairing Not Allowed",
    0x19: "Unknown LMP PDU",
    0x1B: "SCO Offset Rejected",
    0x1C: "SCO Interval Rejected",
    0x1D: "SCO Air Mode Rejected",
    0x1E: "Invalid LMP/LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LMP/LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x23: "LMP Error Transaction Collision / LL Procedure Collision",
    0x24: "LMP PDU Not Allowed",
}

# IEEE 802.11 reason codes (Eggbot gap fill). 12 and 25-31 are reserved.
WIFI_EGGBOT_FILLED = {
    10: "Disassociated: unacceptable Power Capability element",
    11: "Disassociated: unacceptable Supported Channels element",
    12: "Reserved",
    13: "Invalid information element",
    14: "Message integrity code (MIC) failure",
    21: "Unsupported RSN information element version",
    22: "Invalid RSN information element capabilities",
    24: "Cipher suite rejected because of security policy",
    25: "Reserved",
    26: "Reserved",
    27: "Reserved",
    28: "Reserved",
    29: "Reserved",
    30: "Reserved",
    31: "Reserved",
    32: "Disassociated for unspecified QoS-related reason",
    33: "Disassociated: QoS AP lacks sufficient bandwidth",
}


@pytest.mark.parametrize("code,name", sorted(HCI_EGGBOT_FILLED.items()))
def test_hci_status_eggbot_gaps_resolve(code, name):
    assert HCI_STATUS_NAMES[code] == name
    assert _status_name(code) == name


def test_hci_status_unknown_stays_unknown():
    # 0xFF is not assigned in Core Spec Part F; must not invent a name.
    assert 0xFF not in HCI_STATUS_NAMES
    assert _status_name(0xFF) == "Unknown (0xFF)"
    # 0x2B is unused in the Core Spec list (gap between 0x2A and 0x2C).
    assert 0x2B not in HCI_STATUS_NAMES
    assert _status_name(0x2B) == "Unknown (0x2B)"


@pytest.mark.parametrize("code,name", sorted(WIFI_EGGBOT_FILLED.items()))
def test_wifi_reason_eggbot_gaps_resolve(code, name):
    assert REASON_CODE_NAMES[code] == name
    assert _reason_name(code) == name


def test_wifi_reason_unknown_stays_unknown():
    # 99 is outside the commonly assigned reason-code range; leave Unknown.
    assert 99 not in REASON_CODE_NAMES
    assert _reason_name(99) == "Unknown (802.11 reason 99)"


def test_hci_preexisting_fixture_codes_unchanged():
    # PC-bt-hci-001 / 002 ground truth from issue #65.
    assert _status_name(0x05) == "Authentication Failure"
    assert _status_name(0x08) == "Connection Timeout"


def test_wifi_preexisting_reason_15_unchanged():
    # PC-wifi-002 ground truth from issue #66.
    assert _reason_name(15) == "4-way handshake timeout"
