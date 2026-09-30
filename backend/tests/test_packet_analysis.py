"""Regression tests for the packet-analysis fallback backend
(app/parsers/packet_analysis.py).

Real .pcap test files used to build/verify this parser are two ~30-90MB
802.11 monitor-mode captures (not committed -- too big), used to:
  - Benchmark that generic scapy per-packet dissection is far too slow at
    real capture sizes (>120s for one RadioTap layer per packet on a
    297,262-packet file) -- this is WHY the fallback backend hand-parses
    radiotap/802.11 headers directly instead of using scapy for the hot
    path.
  - Verify the hand-rolled RSSI (dBm Antenna Signal) extraction exactly
    matches scapy's own RadioTap.dBm_AntSignal decoding (0 mismatches
    across 3000 real packets) before trusting it for a full-file run.
  - Confirm real signal is found: SSID "pixel_simhouse" (the same SSID the
    wifi.py parser separately found a disconnection event for in the
    matching bugreport), multiple BSSIDs, and 24 real deauthentication
    frames with source MAC addresses.

These tests use small synthetic pcap files built from scratch instead,
pinning down the exact byte-level parsing so a regression is caught without
needing the large real files.
"""
from __future__ import annotations

import struct

import pytest

from app.parsers.packet_analysis import (
    TSHARK_FIELDS,
    _analyze_dot11_fallback,
    _decode_tshark_ssid,
    _dot11_frame_control,
    _radiotap_rssi_and_header_len,
    _tshark_truthy,
    analyze_packet_capture,
    analyze_with_tshark,
    dot11_frame_label,
    tshark_available,
)

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"


def _pcap_global_header(linktype: int) -> bytes:
    return PCAP_MAGIC_LE + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, linktype)


def _pcap_record(pkt: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt


def _radiotap_with_rssi(rssi_dbm: int) -> bytes:
    # present = bit5 only (dBm Antenna Signal). No fields before it, so the
    # RSSI byte sits immediately after the 8-byte radiotap header.
    present = 1 << 5
    header = struct.pack("<BBHI", 0, 0, 9, present)
    rssi_byte = bytes([rssi_dbm & 0xFF])  # two's complement for negative dBm
    return header + rssi_byte  # 9 bytes total


def _dot11_frame_control_bytes(ftype: int, subtype: int, retry: bool = False) -> bytes:
    byte0 = ((subtype & 0xF) << 4) | ((ftype & 0x3) << 2)
    byte1 = 0x08 if retry else 0x00
    return bytes([byte0, byte1])


def _dot11_mgmt_header(ftype: int, subtype: int, addr2: bytes, retry: bool = False) -> bytes:
    fc = _dot11_frame_control_bytes(ftype, subtype, retry)
    duration = b"\x00\x00"
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr3 = b"\x11\x22\x33\x44\x55\x66"
    seqctl = b"\x00\x00"
    return fc + duration + addr1 + addr2 + addr3 + seqctl


def _beacon_with_ssid(addr2: bytes, ssid: str) -> bytes:
    header = _dot11_mgmt_header(0, 8, addr2)  # type=Management, subtype=Beacon
    fixed = b"\x00" * 8 + b"\x00\x00" + b"\x01\x04"  # Timestamp(8) + Interval(2) + CapInfo(2)
    ie = bytes([0, len(ssid)]) + ssid.encode("utf-8")  # tag 0 = SSID
    return header + fixed + ie


def test_radiotap_rssi_extraction_matches_expected_byte_offset():
    pkt = _radiotap_with_rssi(-71) + _dot11_frame_control_bytes(0, 12)
    rssi, rt_len = _radiotap_rssi_and_header_len(pkt)
    assert rssi == -71
    assert rt_len == 9


def test_dot11_frame_control_parses_type_subtype_and_retry():
    pkt = _radiotap_with_rssi(-50) + _dot11_frame_control_bytes(0, 12, retry=True)
    rssi, rt_len = _radiotap_rssi_and_header_len(pkt)
    parsed = _dot11_frame_control(pkt, rt_len)
    assert parsed == (0, 12, True)
    assert dot11_frame_label(0, 12) == "Deauthentication"


def test_fallback_backend_finds_deauth_beacon_ssid_and_rssi_range(tmp_path):
    deauth_pkt = _radiotap_with_rssi(-60) + _dot11_mgmt_header(
        0, 12, addr2=b"\xaa\xbb\xcc\xdd\xee\xff"
    )
    beacon_pkt = _radiotap_with_rssi(-40) + _beacon_with_ssid(
        addr2=b"\x11\x22\x33\x44\x55\x66", ssid="test_network"
    )
    retry_data_pkt = _radiotap_with_rssi(-80) + _dot11_frame_control_bytes(2, 0, retry=True)

    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(
        _pcap_global_header(127)  # Radiotap linktype
        + _pcap_record(deauth_pkt)
        + _pcap_record(beacon_pkt)
        + _pcap_record(retry_data_pkt)
    )

    result = _analyze_dot11_fallback(pcap_path)
    assert result.backend == "fallback"
    assert result.packets_analyzed == 3
    assert result.rssi_min_dbm == -80
    assert result.rssi_max_dbm == -40
    assert result.retry_count == 1

    labels = {f.label: f.count for f in result.frame_type_breakdown}
    assert labels["Deauthentication"] == 1
    assert labels["Beacon"] == 1
    assert labels["Data"] == 1

    ssids = {s.value for s in result.identity_signals if s.kind == "ssid"}
    assert "test_network" in ssids

    assert len(result.anomalies) == 1
    assert result.anomalies[0].kind == "deauthentication"
    assert result.anomalies[0].mac_or_ip == "aa:bb:cc:dd:ee:ff"


def test_analyze_packet_capture_uses_fallback_when_tshark_unavailable(tmp_path, monkeypatch):
    import app.parsers.packet_analysis as pa_module

    monkeypatch.setattr(pa_module, "tshark_available", lambda: False)

    pkt = _radiotap_with_rssi(-55) + _dot11_frame_control_bytes(0, 8)  # Beacon, no IEs
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_global_header(127) + _pcap_record(pkt))

    result = analyze_packet_capture(pcap_path, linktype=127)
    assert result is not None
    assert result.backend == "fallback"
    assert result.link_layer == "802.11"


def test_analyze_packet_capture_returns_none_for_unsupported_linktype(tmp_path):
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_global_header(0) + _pcap_record(b"\x00" * 20))
    result = analyze_packet_capture(pcap_path, linktype=0)  # linktype 0 = unsupported here
    assert result is None


# ---------------------------------------------------------------------------
# tshark backend regressions (issues #67, #68, #69) -- mock _run_tshark_fields
# row output pinned to the exact shapes QA captured against Wireshark 4.4.18.
# A gated live-tshark test below exercises the real binary when present.
# ---------------------------------------------------------------------------

def _tshark_row(**field_values: str) -> list[str]:
    """Build one tshark `-T fields` row in TSHARK_FIELDS order, defaulting
    unspecified fields to "" (tshark's own empty-field representation).
    Keyed by field name rather than position so this doesn't silently
    break if TSHARK_FIELDS is ever reordered.
    """
    return [field_values.get(f, "") for f in TSHARK_FIELDS]


def test_tshark_fields_uses_current_wireshark_reason_code_name():
    # PC-pcap-001 / #67: wlan_mgt.fixed.reason_code was removed in
    # Wireshark 4.x; an unknown -e field aborts the WHOLE tshark
    # invocation (exit 1), silently falling back for every capture.
    # Membership alone is weak against the *next* rename — the gated
    # live_tshark test below is the real guard; this pins the known swap.
    assert "wlan_mgt.fixed.reason_code" not in TSHARK_FIELDS
    assert "wlan.fixed.reason_code" in TSHARK_FIELDS
    assert TSHARK_FIELDS.index("wlan.fixed.reason_code") == 6


def test_analyze_with_tshark_decodes_deauth_reason_code(monkeypatch, tmp_path):
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{
        "wlan.fc.type": "0", "wlan.fc.subtype": "12",
        "wlan.bssid": "aa:bb:cc:dd:ee:ff",
        "wlan.fixed.reason_code": "0x0003",
    })
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "802.11")
    assert result.backend == "tshark"
    assert len(result.anomalies) == 1
    assert result.anomalies[0].kind == "deauthentication"
    assert "0x0003" in result.anomalies[0].detail


def test_analyze_with_tshark_detects_tcp_reset_as_true_text(monkeypatch, tmp_path):
    # PC-pcap-002 / #68: modern tshark emits boolean fields as "True"/
    # "False" text, not "1"/"0" -- the old `== "1"` check silently never
    # matched, dropping every TCP RST on the tshark backend.
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{
        "ip.src": "203.0.113.10", "ip.dst": "198.51.100.20",
        "tcp.flags.reset": "True",
    })
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "ethernet")
    resets = [a for a in result.anomalies if a.kind == "tcp_reset"]
    assert len(resets) == 1
    assert resets[0].detail == "TCP RST 203.0.113.10 -> 198.51.100.20"


def test_analyze_with_tshark_still_detects_tcp_reset_as_1_text(monkeypatch, tmp_path):
    # Older tshark's numeric-boolean output shape must keep working too.
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{"tcp.flags.reset": "1"})
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "ethernet")
    assert any(a.kind == "tcp_reset" for a in result.anomalies)


def test_decode_tshark_ssid_converts_hex_bytes_to_network_name():
    # PC-pcap-003 / #69: wlan.ssid is FT_BYTES; `-T fields` emits raw hex,
    # not the decoded SSID string (fixture from issue #69: "SYNTH_PCAP_QA").
    assert _decode_tshark_ssid("53594e54485f504341505f5141") == "SYNTH_PCAP_QA"


def test_decode_tshark_ssid_handles_colon_separated_hex():
    # Some tshark builds/preferences render FT_BYTES colon-separated.
    assert _decode_tshark_ssid("53:59:4e:54") == "SYNT"


def test_decode_tshark_ssid_falls_back_to_raw_value_on_invalid_hex():
    # Defensive: an unexpected (non-hex) value must not raise or vanish.
    assert _decode_tshark_ssid("not-hex!!") == "not-hex!!"


def test_analyze_with_tshark_ssid_identity_signal_is_decoded(monkeypatch, tmp_path):
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{
        "wlan.ssid": "53594e54485f504341505f5141",
        "wlan.bssid": "aa:bb:cc:dd:ee:ff",
    })
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "802.11")
    ssids = {s.value for s in result.identity_signals if s.kind == "ssid"}
    assert ssids == {"SYNTH_PCAP_QA"}


def test_tshark_truthy_accepts_true_false_and_numeric():
    assert _tshark_truthy("True") is True
    assert _tshark_truthy("true") is True
    assert _tshark_truthy("1") is True
    assert _tshark_truthy("False") is False
    assert _tshark_truthy("false") is False
    assert _tshark_truthy("0") is False
    assert _tshark_truthy("") is False


def test_analyze_with_tshark_counts_retry_as_true_text(monkeypatch, tmp_path):
    # Same boolean trap as #68 / tcp.flags.reset: modern tshark emits
    # wlan.fc.retry as "True"/"False". The old `== "1"` check left
    # retry_count at 0 and retry_rate_pct at 0.0 (confidently wrong).
    import app.parsers.packet_analysis as pa_module

    rows = [
        _tshark_row(**{
            "wlan.fc.type": "2", "wlan.fc.subtype": "0",
            "wlan.fc.retry": "True",
        }),
        _tshark_row(**{
            "wlan.fc.type": "2", "wlan.fc.subtype": "0",
            "wlan.fc.retry": "False",
        }),
    ]
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: rows)

    result = analyze_with_tshark(tmp_path / "unused.pcap", "802.11")
    assert result.retry_count == 1
    assert result.retry_rate_pct == 50.0


def test_analyze_with_tshark_still_counts_retry_as_1_text(monkeypatch, tmp_path):
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{
        "wlan.fc.type": "2", "wlan.fc.subtype": "0",
        "wlan.fc.retry": "1",
    })
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "802.11")
    assert result.retry_count == 1
    assert result.retry_rate_pct == 100.0


def test_decode_tshark_ssid_replaces_non_utf8_bytes_like_fallback():
    # Parity with _dot11_ssid_from_ies: errors="replace" -> U+FFFD per bad byte.
    assert _decode_tshark_ssid("fffefd") == "���"


def test_decode_tshark_ssid_treats_hidden_or_missing_as_absent():
    # Zero-length / wildcard SSID: tshark may emit "" or literal "<MISSING>".
    # Fallback returns None for tag_len == 0; match that (no identity signal).
    assert _decode_tshark_ssid("") is None
    assert _decode_tshark_ssid("<MISSING>") is None


def test_analyze_with_tshark_skips_hidden_ssid_identity(monkeypatch, tmp_path):
    import app.parsers.packet_analysis as pa_module

    row = _tshark_row(**{"wlan.ssid": "<MISSING>", "wlan.bssid": "aa:bb:cc:dd:ee:ff"})
    monkeypatch.setattr(pa_module, "_run_tshark_fields", lambda path: [row])

    result = analyze_with_tshark(tmp_path / "unused.pcap", "802.11")
    ssids = [s for s in result.identity_signals if s.kind == "ssid"]
    assert ssids == []
    assert any(s.kind == "bssid" and s.value == "aa:bb:cc:dd:ee:ff" for s in result.identity_signals)


@pytest.mark.skipif(not tshark_available(), reason="tshark not on PATH")
def test_live_tshark_dissects_synthetic_80211_fixture(tmp_path):
    # End-to-end against real tshark (gated): catches the next renamed -e
    # field the way mock membership alone cannot (#67 acceptance).
    deauth_pkt = (
        _radiotap_with_rssi(-60)
        + _dot11_mgmt_header(0, 12, addr2=b"\xaa\xbb\xcc\xdd\xee\xff")
        + b"\x03\x00"  # reason code 3
    )
    beacon_pkt = _radiotap_with_rssi(-40) + _beacon_with_ssid(
        addr2=b"\x11\x22\x33\x44\x55\x66", ssid="SYNTH_PCAP_QA"
    )
    retry_data_pkt = (
        _radiotap_with_rssi(-80)
        + _dot11_frame_control_bytes(2, 0, retry=True)
        + b"\x00" * 22
    )
    pcap_path = tmp_path / "live_synth.pcap"
    pcap_path.write_bytes(
        _pcap_global_header(127)
        + _pcap_record(deauth_pkt)
        + _pcap_record(beacon_pkt)
        + _pcap_record(retry_data_pkt)
    )

    result = analyze_with_tshark(pcap_path, "802.11")
    assert result.backend == "tshark"
    assert result.packets_analyzed == 3
    assert result.retry_count == 1
    ssids = {s.value for s in result.identity_signals if s.kind == "ssid"}
    assert "SYNTH_PCAP_QA" in ssids
    deauths = [a for a in result.anomalies if a.kind == "deauthentication"]
    assert len(deauths) == 1
    assert "0x0003" in deauths[0].detail
