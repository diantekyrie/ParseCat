"""Round 2: Wi-Fi SM synthetic CI fixtures for PC-wifi-002..006 (issue #66).

Synthetic WifiController `rec[N]:` lines only — lab SSID/BSSID, no real
captures/PII. Expected values come from current `wifi.py` behavior
(`REASON_CODE_NAMES`, `_reason_name`, `DISCONNECT_RE`, `ASSOC_RE`) and from
existing real-fixture assertions (reason 3 / locallyGenerated true).

Does not duplicate BT HCI fixtures from #65/#73.
"""
from __future__ import annotations

from app.parsers.section_extractor import Section
from app.parsers.wifi import REASON_CODE_NAMES, parse_wifi_events, _reason_name

LAB_SSID = "lab-ap-01"
LAB_BSSID = "02:00:00:00:00:01"
LAB_BSSID_ROAM = "02:00:00:00:00:02"


def _section(text: str, *, line_start: int = 1) -> Section:
    lines = text.splitlines()
    return Section(
        name="wifi",
        priority=None,
        line_start=line_start,
        line_end=line_start + len(lines) - 1,
        lines=lines,
        kind="dumpsys",
    )


def _disc_line(
    rec: int,
    ts: str,
    *,
    ssid: str,
    bssid: str,
    reason: int,
    local: str,
) -> str:
    return (
        f'  rec[{rec}]: time={ts} processed=L3ConnectedState org=L3ConnectedState '
        f'dest=DisconnectedState what=NETWORK_DISCONNECTION_EVENT screen=off '
        f'ssid: "{ssid}" bssid: {bssid} reasonCode: {reason} locallyGenerated: {local}'
    )


def _assoc_line(rec: int, ts: str, *, bssid: str, roam: str) -> str:
    return (
        f"  rec[{rec}]: time={ts} processed=L2ConnectedState org=L3ConnectedState "
        f"dest=<null> what=ASSOCIATED_BSSID_EVENT screen=off 0 0 "
        f"BSSID={bssid} Target Bssid=any Last Bssid={bssid} roam={roam}"
    )


# ---- lookup invent-nothing -------------------------------------------------


def test_reason_name_known_codes_match_table():
    # Ground truth pinned by REASON_CODE_NAMES / existing fixture assertions.
    assert _reason_name(15) == "4-way handshake timeout"
    assert REASON_CODE_NAMES[15] == "4-way handshake timeout"
    assert _reason_name(3) == "Deauthenticated: station leaving"
    assert REASON_CODE_NAMES[3] == "Deauthenticated: station leaving"


def test_reason_name_unknown_stays_unknown():
    # PC-wifi-006 ground truth; same fallback as test_hci_wifi_reason_lookups.
    assert 99 not in REASON_CODE_NAMES
    assert _reason_name(99) == "Unknown (802.11 reason 99)"


# ---- PC-wifi-002..006 (#66) -----------------------------------------------


def test_pc_wifi_002_four_way_handshake_timeout():
    """PC-wifi-002: NETWORK_DISCONNECTION_EVENT reasonCode 15."""
    text = _disc_line(
        1, "01-15 10:00:00.100",
        ssid=LAB_SSID, bssid=LAB_BSSID, reason=15, local="false",
    )
    events = parse_wifi_events(_section(text))
    assert len(events) == 1
    e = events[0]
    assert e.kind == "disconnection"
    assert e.ssid == LAB_SSID
    assert e.bssid == LAB_BSSID
    assert e.reason_code == 15
    assert e.reason_name == "4-way handshake timeout"
    assert e.locally_generated is False
    assert e.roam is None
    assert e.source_ref.section == "wifi"
    assert e.source_ref.line_start == 1


def test_pc_wifi_003_non_self_initiated_disconnect():
    """PC-wifi-003: locallyGenerated false (non-self-initiated)."""
    # reason 0 appears in wifi.py module docstring example with local=false.
    text = _disc_line(
        2, "01-15 10:01:00.100",
        ssid=LAB_SSID, bssid=LAB_BSSID, reason=0, local="false",
    )
    events = parse_wifi_events(_section(text, line_start=10))
    assert len(events) == 1
    e = events[0]
    assert e.kind == "disconnection"
    assert e.locally_generated is False
    assert e.reason_code == 0
    assert e.reason_name == "Reserved/unspecified"
    assert e.source_ref.line_start == 10


def test_pc_wifi_004_self_initiated_disconnect():
    """PC-wifi-004: locallyGenerated true (self-initiated).

    Mirrors real-fixture assertion in test_parsers_fixtures.py:
    reason 3 / locallyGenerated true / Deauthenticated: station leaving.
    """
    text = _disc_line(
        3, "01-15 10:02:00.100",
        ssid=LAB_SSID, bssid=LAB_BSSID, reason=3, local="true",
    )
    events = parse_wifi_events(_section(text))
    assert len(events) == 1
    e = events[0]
    assert e.kind == "disconnection"
    assert e.locally_generated is True
    assert e.reason_code == 3
    assert e.reason_name == "Deauthenticated: station leaving"


def test_pc_wifi_005_roam_vs_real_drop():
    """PC-wifi-005: ASSOCIATED_BSSID_EVENT roam=true vs separate disconnect.

    Roam association and NETWORK_DISCONNECTION_EVENT must not be conflated.
    """
    text = "\n".join([
        _assoc_line(4, "01-15 10:03:00.100", bssid=LAB_BSSID_ROAM, roam="true"),
        _assoc_line(5, "01-15 10:03:30.100", bssid=LAB_BSSID, roam="false"),
        _disc_line(
            6, "01-15 10:04:00.100",
            ssid=LAB_SSID, bssid=LAB_BSSID, reason=3, local="true",
        ),
    ])
    events = parse_wifi_events(_section(text))
    assocs = [e for e in events if e.kind == "association"]
    discs = [e for e in events if e.kind == "disconnection"]
    assert len(assocs) == 2
    assert len(discs) == 1
    roam_true = [e for e in assocs if e.roam is True]
    roam_false = [e for e in assocs if e.roam is False]
    assert len(roam_true) == 1 and roam_true[0].bssid == LAB_BSSID_ROAM
    assert len(roam_false) == 1 and roam_false[0].bssid == LAB_BSSID
    # Disconnection is a distinct kind — not an association with roam=false.
    assert discs[0].kind == "disconnection"
    assert discs[0].roam is None
    assert discs[0].locally_generated is True
    assert all(e.kind in {"association", "disconnection"} for e in events)


def test_pc_wifi_006_unknown_reason_maps_to_unknown():
    """PC-wifi-006: unlisted reasonCode → Unknown (802.11 reason N)."""
    text = _disc_line(
        7, "01-15 10:05:00.100",
        ssid=LAB_SSID, bssid=LAB_BSSID, reason=99, local="false",
    )
    events = parse_wifi_events(_section(text))
    assert len(events) == 1
    e = events[0]
    assert e.kind == "disconnection"
    assert e.reason_code == 99
    assert e.reason_name == "Unknown (802.11 reason 99)"
    assert e.locally_generated is False


def test_combined_fixture_covers_all_sm_scenarios():
    """Single multi-rec synthetic log covering PC-wifi-002..006 paths."""
    text = "\n".join([
        _disc_line(10, "01-15 11:00:00.100", ssid=LAB_SSID, bssid=LAB_BSSID, reason=15, local="false"),
        _disc_line(11, "01-15 11:01:00.100", ssid=LAB_SSID, bssid=LAB_BSSID, reason=0, local="false"),
        _disc_line(12, "01-15 11:02:00.100", ssid=LAB_SSID, bssid=LAB_BSSID, reason=3, local="true"),
        _assoc_line(13, "01-15 11:03:00.100", bssid=LAB_BSSID_ROAM, roam="true"),
        _disc_line(14, "01-15 11:04:00.100", ssid=LAB_SSID, bssid=LAB_BSSID, reason=99, local="false"),
    ])
    events = parse_wifi_events(_section(text, line_start=100))
    discs = [e for e in events if e.kind == "disconnection"]
    assocs = [e for e in events if e.kind == "association"]
    assert [(e.reason_code, e.locally_generated, e.reason_name) for e in discs] == [
        (15, False, "4-way handshake timeout"),
        (0, False, "Reserved/unspecified"),
        (3, True, "Deauthenticated: station leaving"),
        (99, False, "Unknown (802.11 reason 99)"),
    ]
    assert len(assocs) == 1 and assocs[0].roam is True
    assert all(e.source_ref.line_start >= 100 for e in events)
