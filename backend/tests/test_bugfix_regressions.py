"""Synthetic regression tests for confirmed parser/scoring bugs.

These do not need the gitignored real bugreport zips.
"""
from __future__ import annotations

import struct
import zipfile
from types import SimpleNamespace

from app.parsers.crash_events import parse_crash_events
from app.parsers.location import parse_gnss_signal_intervals
from app.parsers.packet_analysis import analyze_packet_capture
from app.parsers.section_extractor import (
    DUMPSYS_END_RE,
    DUMPSYS_START_RE,
    Section,
    extract_sections_from_text,
)
from app.parsers import WANTED_SECTIONS
from app.services.ingestion import parse_bugreport_zip
from app.services.reasoning import DEVICE_CONTEXT_LLM_FIELDS, evidence_confidence, score_confidence
from app.services.summary import _timeline_sort_key


def test_cpuinfo_dumpsys_name_maps_to_cpu_info():
    start_line = "DUMP OF SERVICE cpuinfo:"
    end_line = "--------- 0.001s was the duration of dumpsys cpuinfo, ending at: 12:00:00"
    # Fixture lines must match production delimiters; do not change DUMPSYS_*_RE.
    assert DUMPSYS_START_RE.match(start_line)
    assert DUMPSYS_END_RE.match(end_line)
    text = (
        start_line + "\n"
        "Threads: 10 total,   1 running, 9 sleeping,   0 stopped,   0 zombie\n"
        + end_line + "\n"
        "-------------------------------------------------------------------------------\n"
    )
    sections = extract_sections_from_text(text, WANTED_SECTIONS)
    assert "cpu_info" in sections
    assert "cpuinfo" not in sections
    assert any("Threads:" in line for line in sections["cpu_info"].lines)


OOM_CRASH_LINES = """\
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: FATAL EXCEPTION: main
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Process: com.example.app, PID: 2974
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: java.lang.OutOfMemoryError: Failed to allocate a 32 byte allocation
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat dalvik.system.VMRuntime.newNonMovableArray(Native Method)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Caused by: java.lang.OutOfMemoryError: heap space
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat com.example.app.Foo.bar(Foo.java:12)
""".splitlines()


def test_crash_parser_captures_outofmemoryerror():
    section = Section(
        name="system_log", priority=None, line_start=1,
        line_end=len(OOM_CRASH_LINES), lines=OOM_CRASH_LINES, kind="log",
    )
    crashes = parse_crash_events(section)
    assert len(crashes) == 1
    assert crashes[0].exception_class == "java.lang.OutOfMemoryError"
    assert "Failed to allocate" in crashes[0].message
    assert crashes[0].root_cause_class == "java.lang.OutOfMemoryError"
    assert crashes[0].root_cause_message == "heap space"
    assert "Foo.bar" in crashes[0].root_cause_frame


def _minimal_btsnoop_bytes() -> bytes:
    header = b"btsnoop\x00" + struct.pack(">II", 1, 1002)
    payload = bytes([0x01, 0x03, 0x0C, 0x00])  # H4 command
    record = struct.pack(">IIIIQ", len(payload), len(payload), 0, 0, 0x00DCDDB30F2F8000) + payload
    return header + record


def _zip_with_hci(tmp_path, files: dict[str, bytes]):
    zip_path = tmp_path / "synthetic_bugreport.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "bugreport-synthetic-2026-01-01-00-00-00.txt",
            "------ SYSTEM PROPERTIES (getprop) ------\n"
            "[ro.build.version.release]: [15]\n"
            "------ 0.000s was the duration of 'SYSTEM PROPERTIES' ------\n",
        )
        for name, data in files.items():
            zf.writestr(name, data)
    return parse_bugreport_zip(zip_path)


def test_bt_hci_found_under_unknown_oem_filename(tmp_path):
    cap = _zip_with_hci(tmp_path, {
        "FS/data/misc/bluetooth/logs/vendor_hci_snoop.log": _minimal_btsnoop_bytes(),
    })
    assert "No Bluetooth HCI snoop log found" not in cap.parse_warnings
    assert cap.bt_hci_summary is not None
    assert cap.bt_hci_summary.total_packets == 1


def test_bt_hci_falls_through_invalid_first_candidate(tmp_path):
    cap = _zip_with_hci(tmp_path, {
        "FS/data/misc/bluetooth/logs/btsnoop_hci.log.filtered": b"not a btsnoop file",
        "FS/data/misc/bluetooth/logs/btsnoop_hci.log": _minimal_btsnoop_bytes(),
    })
    assert cap.bt_hci_summary is not None
    assert cap.bt_hci_summary.total_packets == 1
    assert not any("did not match the expected btsnoop" in w for w in cap.parse_warnings)


def _gnss_line(ts: str, quality: str) -> str:
    return f"  {ts}.000 094 e2902820 gps_signal_quality={quality}"


def test_gnss_interval_keeps_new_year_wrap():
    lines = [
        _gnss_line("12-31 23:50:00", "poor"),
        _gnss_line("01-01 00:10:00", "good"),
    ]
    section = Section(
        name="batterystats", priority=None, line_start=1,
        line_end=len(lines), lines=lines, kind="dumpsys",
    )
    intervals = parse_gnss_signal_intervals(section)
    assert len(intervals) == 1
    assert intervals[0].quality == "poor"
    assert intervals[0].start_timestamp == "12-31 23:50:00"
    assert intervals[0].end_timestamp == "01-01 00:10:00"
    assert intervals[0].duration_sec == 20 * 60


def test_gnss_interval_still_drops_true_clock_step_back():
    lines = [
        _gnss_line("08-13 18:37:39", "poor"),
        _gnss_line("08-13 18:37:34", "good"),
    ]
    section = Section(
        name="batterystats", priority=None, line_start=1,
        line_end=len(lines), lines=lines, kind="dumpsys",
    )
    assert parse_gnss_signal_intervals(section) == []


def test_score_confidence_does_not_upgrade_on_empty_sibling_captures():
    # One fact in one capture, even if the device has more captures on file.
    one = [SimpleNamespace(capture_id=1)]
    label, _ = evidence_confidence(one)
    assert label == "LOW"
    two_caps = [SimpleNamespace(capture_id=1), SimpleNamespace(capture_id=2)]
    label, _ = evidence_confidence(two_caps)
    assert label == "HIGH"
    assert score_confidence(1, 2)[0] == "MEDIUM"  # old call shape still defined


def test_device_context_allowlist_excludes_serial():
    assert "serial" not in DEVICE_CONTEXT_LLM_FIELDS
    assert "build_fingerprint" in DEVICE_CONTEXT_LLM_FIELDS
    assert "kernel" in DEVICE_CONTEXT_LLM_FIELDS


def test_timeline_sort_key_orders_iso_hci_with_logcat():
    logcat = "08-14 10:00:00.000"
    hci_earlier = "2026-08-14T09:59:00.000Z"
    hci_later = "2026-08-14T10:01:00.000Z"
    ordered = sorted([logcat, hci_later, hci_earlier], key=_timeline_sort_key)
    assert ordered == [hci_earlier, logcat, hci_later]



PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"


def _pcap_global_header(linktype: int) -> bytes:
    return PCAP_MAGIC_LE + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, linktype)


def _pcap_record(pkt: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt


def _radiotap_with_rssi(rssi_dbm: int) -> bytes:
    present = 1 << 5
    header = struct.pack("<BBHI", 0, 0, 9, present)
    rssi_byte = bytes([rssi_dbm & 0xFF])
    return header + rssi_byte


def _dot11_frame_control_bytes(ftype: int, subtype: int, retry: bool = False) -> bytes:
    byte0 = ((subtype & 0xF) << 4) | ((ftype & 0x3) << 2)
    byte1 = 0x08 if retry else 0x00
    return bytes([byte0, byte1])


def test_tshark_failure_records_warning_and_falls_back(tmp_path, monkeypatch):
    import app.parsers.packet_analysis as pa_module

    monkeypatch.setattr(pa_module, "tshark_available", lambda: True)

    def boom(*_a, **_k):
        raise RuntimeError("tshark exploded")

    monkeypatch.setattr(pa_module, "analyze_with_tshark", boom)

    pkt = _radiotap_with_rssi(-55) + _dot11_frame_control_bytes(0, 8)
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_global_header(127) + _pcap_record(pkt))
    warnings: list[str] = []
    result = analyze_packet_capture(pcap_path, linktype=127, warnings=warnings)
    assert result is not None
    assert result.backend == "fallback"
    assert warnings
    assert "tshark" in warnings[0].lower()
