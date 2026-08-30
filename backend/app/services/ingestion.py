"""Orchestrates turning an uploaded bugreport zip into a ParsedCapture of
structured facts. This is the only place raw bugreport text gets touched;
everything downstream (verification, correlation, LLM reasoning) works off
ParsedCapture / persisted rows, never re-parses raw text.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.parsers import WANTED_SECTIONS, ParsedCapture
from app.parsers.anr import parse_anr, parse_anr_trace_dump
from app.parsers.audio_focus import parse_audio_focus
from app.parsers.battery_stats import parse_battery_uid_stats
from app.parsers.bt_hci import parse_bt_hci_log
from app.parsers.cdm_pairing import parse_cdm_pairing_events
from app.parsers.companion_device import parse_companion_device_associations
from app.parsers.crash_events import parse_crash_events
from app.parsers.device_info import parse_device_info
from app.parsers.foreground_service import parse_foreground_services
from app.parsers.freeze_events import parse_freeze_events
from app.parsers.logcat_history import parse_logcat_history
from app.parsers.media_session import parse_media_sessions
from app.parsers.package_info import parse_packages
from app.parsers.packet_analysis import analyze_packet_capture
from app.parsers.pcap import parse_pcap
from app.parsers.cpu import parse_cpu_snapshot
from app.parsers.kernel import parse_kernel_log
from app.parsers.location import parse_gnss_signal_intervals, parse_location_dump
from app.parsers.thermal import parse_thermal_snapshot
from app.parsers.memory import parse_meminfo, parse_memory_samples
from app.parsers.process_kills import parse_process_kills
from app.parsers.section_extractor import extract_sections, extract_sections_from_text
from app.parsers.selinux import parse_selinux_denials
from app.parsers.tombstone import parse_tombstone
from app.parsers.wifi import parse_wifi_events

def _dedup_by_key(events: list, key_fn) -> list:
    """Keeps the first occurrence of each distinct key, dropping later
    ones. Used when merging system_log-derived events with logcat-history
    events: the on-device persistent buffer and the live logcat capture at
    dump time can genuinely overlap in time, printing the identical event
    to both -- same content, different file. Since the system_log-derived
    list is always concatenated first, this keeps that citation (the more
    familiar section name) over an identical logcat.NN duplicate, while
    leaving every non-duplicate historical event untouched.
    """
    seen = set()
    out = []
    for e in events:
        k = key_fn(e)
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out


TOMBSTONE_PREFIX = "FS/data/tombstones/"
ANR_PREFIX = "FS/data/anr/"
BT_HCI_LOG_DIR = "FS/data/misc/bluetooth/logs/"
# Real gap found live: both real test bugreports (a Pixel phone and a Pixel
# Watch, different Android builds) ship this file as
# "btsnoop_hci.log.filtered", not "btsnooz_hci.log" -- the one hardcoded
# path this parser originally looked for. That name never matched, so the
# HCI parser silently never ran on either real capture despite a real,
# valid 4MB+ classic-btsnoop log sitting in the zip the whole time; the
# "No Bluetooth HCI snoop log found" warning was a false negative, not a
# true absence. OEM/build variation in this filename (.filtered, .last
# rotated copies, no suffix at all) means a single hardcoded name isn't
# reliable -- search the directory instead and verify by magic bytes
# (parse_bt_hci_log already returns None on a non-match), preferring the
# primary log over a ".last" rotated copy.
BT_HCI_LOG_CANDIDATES = (
    "btsnoop_hci.log.filtered",
    "btsnoop_hci.log",
    "btsnooz_hci.log",
    "btsnoop_hci.log.filtered.last",
    "btsnoop_hci.log.last",
)


def _zip_entry_modified_at(info: zipfile.ZipInfo) -> str:
    return (f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} "
            f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}")


def parse_tombstones(zf: zipfile.ZipFile) -> list:
    out = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(TOMBSTONE_PREFIX) or name.endswith(".pb"):
            continue
        base = name[len(TOMBSTONE_PREFIX):]
        if "/" in base or not base.startswith("tombstone_"):
            continue
        text = zf.read(name).decode("utf-8", errors="replace")
        out.append(parse_tombstone(base, _zip_entry_modified_at(info), text))
    out.sort(key=lambda t: t.modified_at)
    return out


def parse_anrs(zf: zipfile.ZipFile) -> list:
    out = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(ANR_PREFIX):
            continue
        base = name[len(ANR_PREFIX):]
        if "/" in base or not base.startswith("anr_"):
            continue
        text = zf.read(name).decode("utf-8", errors="replace")
        out.append(parse_anr(base, text))
    out.sort(key=lambda a: a.filename)
    return out


def parse_anr_trace_dumps(zf: zipfile.ZipFile) -> list:
    """trace_<N> files -- full DALVIK THREADS dumps written for an ANR'd
    process. No reliable filename links a trace_N to its anr_* record (none
    observed in real captures), so these are gathered as their own
    self-standing evidence rather than force-matched to one."""
    out = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(ANR_PREFIX):
            continue
        base = name[len(ANR_PREFIX):]
        if "/" in base or not base.startswith("trace_"):
            continue
        text = zf.read(name).decode("utf-8", errors="replace")
        out.extend(parse_anr_trace_dump(base, text))
    return out


def _parse_sections_into_capture(capture: ParsedCapture, sections: dict) -> ParsedCapture:
    """Run every section parser over already-extracted bugreport sections."""
    if "audio" in sections:
        capture.focus_stack, capture.focus_events = parse_audio_focus(sections["audio"])
    else:
        capture.parse_warnings.append("No 'audio' dumpsys section found")

    if "package" in sections:
        capture.packages = parse_packages(sections["package"])
    else:
        capture.parse_warnings.append("No 'package' dumpsys section found")

    if "batterystats" in sections:
        capture.battery_uid_stats = parse_battery_uid_stats(sections["batterystats"])
        # Attribute each UID to a package by matching uid % 100000 against
        # a known package's appId (appId is user-independent; the modulus
        # strips the userId*100000 term regardless of which user the UID
        # belongs to). Real gap found on the first real-data run: several
        # system appIds (1000, 1001, ...) are shared by a dozen-plus
        # packages via android:sharedUserId ("com.android.location.fused"
        # is one of 18 packages sharing appId 1000, the "system" UID) --
        # attributing that battery entry to whichever one happened to be
        # first in the dict would misrepresent a shared system UID's
        # activity as one specific app's. Only attribute when the appId is
        # unique to exactly one installed package; leave it unattributed
        # (not guessed) otherwise, same principle as tombstone/native-crash
        # attribution.
        app_id_owners: dict[int, list[str]] = {}
        for p in capture.packages.values():
            if p.app_id is not None:
                app_id_owners.setdefault(p.app_id, []).append(p.package)
        for stat in capture.battery_uid_stats:
            owners = app_id_owners.get(stat.uid % 100000, [])
            stat.package = owners[0] if len(owners) == 1 else None
    else:
        capture.parse_warnings.append("No 'batterystats' dumpsys section found")

    if "media_session" in sections:
        capture.media_sessions = parse_media_sessions(sections["media_session"])
    else:
        capture.parse_warnings.append("No 'media_session' dumpsys section found")

    if "activity" in sections:
        capture.foreground_services = parse_foreground_services(sections["activity"])
    else:
        capture.parse_warnings.append("No 'activity' dumpsys section found")

    if "system_log" in sections:
        capture.freeze_events = parse_freeze_events(sections["system_log"])
        capture.crash_events = parse_crash_events(sections["system_log"])
        capture.cdm_pairing_events = parse_cdm_pairing_events(sections["system_log"])
    else:
        capture.parse_warnings.append("No 'SYSTEM LOG' section found")

    if "wifi" in sections:
        capture.wifi_events = parse_wifi_events(sections["wifi"])
    else:
        capture.parse_warnings.append("No 'wifi' dumpsys section found")

    # AVC denials appear in both buffers -- overwhelmingly EVENT LOG (where
    # auditd writes) but occasionally SYSTEM LOG too, so both are scanned and
    # the results concatenated. Each denial keeps its own section in its
    # SourceRef, so citations stay accurate either way.
    selinux_denials = []
    for section_name in ("event_log", "system_log"):
        if section_name in sections:
            selinux_denials.extend(parse_selinux_denials(sections[section_name]))
    capture.selinux_denials = selinux_denials
    # am_kill / am_proc_died are written to the EVENT LOG buffer, same as
    # AVC denials.
    if "event_log" in sections:
        capture.process_kills = parse_process_kills(sections["event_log"])
        # am_pss lives in the EVENT LOG alongside am_kill -- both are
        # ActivityManager events, not SYSTEM LOG messages.
        capture.memory_samples = parse_memory_samples(sections["event_log"])

    if "meminfo" in sections:
        capture.memory_snapshot = parse_meminfo(sections["meminfo"])

    if "location" in sections:
        capture.location_snapshot = parse_location_dump(sections["location"])

    if "kernel_log" in sections:
        capture.kernel_log_events = parse_kernel_log(sections["kernel_log"])

    if "thermalservice" in sections:
        capture.thermal_snapshot = parse_thermal_snapshot(sections["thermalservice"])

    if "cpu_info" in sections:
        capture.cpu_load_snapshot = parse_cpu_snapshot(sections["cpu_info"])

    if "batterystats" in sections:
        # gps_signal_quality transitions live in the batterystats HISTORY,
        # not in dumpsys location -- they are the only time-resolved measure
        # of GPS reception anywhere in a bugreport.
        capture.gnss_signal_intervals = parse_gnss_signal_intervals(sections["batterystats"])
    if "event_log" not in sections:
        capture.parse_warnings.append("No 'EVENT LOG' section found (SELinux denials may be undercounted)")

    if "companiondevice" in sections:
        capture.companion_device_associations = parse_companion_device_associations(sections["companiondevice"])
    else:
        capture.parse_warnings.append("No 'companiondevice' dumpsys section found")

    capture.device_info = parse_device_info(
        sections.get("preamble"), sections.get("system_properties")
    )
    if "preamble" not in sections:
        capture.parse_warnings.append("No preamble header block found")
    if "system_properties" not in sections:
        capture.parse_warnings.append("No 'SYSTEM PROPERTIES' section found")

    return capture


def parse_bugreport_zip(zip_path: str | Path) -> ParsedCapture:
    capture = ParsedCapture()

    with zipfile.ZipFile(zip_path) as zf:
        sections = extract_sections(zf, WANTED_SECTIONS)
        capture.tombstones = parse_tombstones(zf)
        capture.anrs = parse_anrs(zf)
        capture.anr_main_thread_snapshots = parse_anr_trace_dumps(zf)

        names = set(zf.namelist())
        bt_hci_path = next(
            (BT_HCI_LOG_DIR + name for name in BT_HCI_LOG_CANDIDATES if BT_HCI_LOG_DIR + name in names),
            None,
        )
        if bt_hci_path is not None:
            capture.bt_hci_summary = parse_bt_hci_log(zf.read(bt_hci_path))
            if capture.bt_hci_summary is None:
                capture.parse_warnings.append(
                    f"Found '{bt_hci_path}' but it did not match the expected btsnoop binary format"
                )
        else:
            capture.parse_warnings.append("No Bluetooth HCI snoop log found")

        history_freezes, history_crashes, history_cdm = parse_logcat_history(zf)

    capture = _parse_sections_into_capture(capture, sections)
    # Merge in facts found in the persistent rotated logcat.NN buffer files
    # (history beyond the live "system_log" window). The live capture and
    # a rotated file can genuinely overlap in time (same event flushed to
    # both), so this dedups on content, not just appends -- otherwise an
    # overlapping event would double its apparent corroboration count for
    # no real reason.
    capture.freeze_events = _dedup_by_key(
        capture.freeze_events + history_freezes,
        lambda e: (e.timestamp, e.event_type, e.pid, e.process),
    )
    capture.crash_events = _dedup_by_key(
        capture.crash_events + history_crashes,
        lambda e: (e.timestamp, e.thread, e.package, e.pid, e.exception_class, e.message),
    )
    capture.cdm_pairing_events = _dedup_by_key(
        capture.cdm_pairing_events + history_cdm,
        lambda e: (e.timestamp, e.tag, e.kind, e.detail),
    )
    return capture


def parse_bugreport_txt(txt_path: str | Path) -> ParsedCapture:
    with Path(txt_path).open("r", encoding="utf-8", errors="replace", newline="\n") as f:
        text = f.read()
    capture = ParsedCapture()
    sections = extract_sections_from_text(text, WANTED_SECTIONS)
    capture.parse_warnings.append("Raw .txt upload: ZIP-only tombstone, ANR, and Bluetooth HCI files are not available")
    return _parse_sections_into_capture(capture, sections)


def parse_pcap_file(path: str | Path) -> ParsedCapture:
    capture = ParsedCapture()
    capture.packet_capture_summary = parse_pcap(Path(path).read_bytes())
    try:
        capture.packet_analysis = analyze_packet_capture(
            Path(path), capture.packet_capture_summary.linktype
        )
    except Exception as exc:  # noqa: BLE001 -- protocol analysis is additive; a
        # failure here must not lose the container-metadata summary above.
        capture.parse_warnings.append(f"Packet-level protocol analysis failed: {exc}")
    if capture.packet_analysis is None and not capture.parse_warnings:
        capture.parse_warnings.append(
            f"Packet-level protocol analysis not available for linktype "
            f"{capture.packet_capture_summary.linktype} ({capture.packet_capture_summary.linktype_name})"
        )
    return capture


def parse_capture_file(path: str | Path, filename: str | None = None) -> ParsedCapture:
    suffix = Path(filename or path).suffix.lower()
    if suffix == ".zip":
        return parse_bugreport_zip(path)
    if suffix == ".txt":
        return parse_bugreport_txt(path)
    if suffix in {".pcap", ".pcapng"}:
        return parse_pcap_file(path)
    raise ValueError("Unsupported upload type; expected .zip, .txt, .pcap, or .pcapng")
