"""Builds the dashboard summary for one capture: device info, fact counts,
top freeze/unfreeze offenders, and a merged chronological timeline of
everything with a timestamp (crashes, freeze/unfreeze, focus events, ANRs,
tombstones, Bluetooth HCI events). All of it reads back rows already
persisted at ingestion time -- nothing here re-parses the bugreport.
"""
from __future__ import annotations

import json

from sqlmodel import Session, func, select

# Same ladder as Android's own IThermal ThrottlingSeverity enum (see
# app/parsers/thermal.py's STATUS_NAMES) -- higher means worse. Used only
# to pick the single worst status across a device's merged captures, never
# to invent a severity from a temperature ourselves.
_THERMAL_SEVERITY_RANK = {
    "none": 0, "light": 1, "moderate": 2, "severe": 3,
    "critical": 4, "emergency": 5, "shutdown": 6,
}

from app.models.db_models import (
    AnrRow,
    CpuLoadSnapshotRow,
    KernelLogEventRow,
    ThermalSnapshotRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    Capture,
    CrashEventRow,
    DeviceInfoRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    MediaSessionRow,
    PackageFactRow,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
    GnssSignalIntervalRow,
    LocationAppUsageRow,
    LocationProviderRow,
    LocationSnapshotRow,
    MemorySnapshotRow,
    ProcessKillEventRow,
    ProcessMemorySampleRow,
    ProcessMemoryUsageRow,
    SelinuxDenialRow,
    TombstoneRow,
    WifiEventRow,
)


def _source(section: str, start: int, end: int) -> dict:
    return {"section": section, "line_start": start, "line_end": end}


def capture_severity(session: Session, capture_id: int) -> dict:
    """Cheap counts used to badge a capture in a list (sidebar, investigation
    picker) before it's actually opened -- not a substitute for the full
    summary, just enough to answer "does this one need attention."
    """
    java_crashes = len(session.exec(select(CrashEventRow).where(CrashEventRow.capture_id == capture_id)).all())
    native_crashes = len(session.exec(select(TombstoneRow).where(TombstoneRow.capture_id == capture_id)).all())
    anrs = len(session.exec(select(AnrRow).where(AnrRow.capture_id == capture_id)).all())
    wifi_disconnects = len(session.exec(
        select(WifiEventRow).where(WifiEventRow.capture_id == capture_id, WifiEventRow.kind == "disconnection")
    ).all())
    return {
        "java_crashes": java_crashes,
        "native_crashes": native_crashes,
        "anrs": anrs,
        "wifi_disconnects": wifi_disconnects,
        "has_findings": (java_crashes + native_crashes + anrs + wifi_disconnects) > 0,
    }


def build_capture_summary(session: Session, capture_id: int) -> dict:
    capture = session.get(Capture, capture_id)
    if capture is None:
        return {}

    device_info_row = session.exec(
        select(DeviceInfoRow).where(DeviceInfoRow.capture_id == capture_id)
    ).first()

    counts = {
        "packages": session.exec(
            select(func.count()).select_from(PackageFactRow).where(PackageFactRow.capture_id == capture_id)
        ).one(),
        "focus_events": session.exec(
            select(func.count()).select_from(FocusEventRow).where(FocusEventRow.capture_id == capture_id)
        ).one(),
        "focus_stack_entries": session.exec(
            select(func.count()).select_from(FocusStackEntryRow).where(FocusStackEntryRow.capture_id == capture_id)
        ).one(),
        "media_sessions": session.exec(
            select(func.count()).select_from(MediaSessionRow).where(MediaSessionRow.capture_id == capture_id)
        ).one(),
        "foreground_services": session.exec(
            select(func.count()).select_from(ForegroundServiceRow).where(ForegroundServiceRow.capture_id == capture_id)
        ).one(),
        "java_crashes": session.exec(
            select(func.count()).select_from(CrashEventRow).where(CrashEventRow.capture_id == capture_id)
        ).one(),
        "native_crashes": session.exec(
            select(func.count()).select_from(TombstoneRow).where(TombstoneRow.capture_id == capture_id)
        ).one(),
        "anrs": session.exec(
            select(func.count()).select_from(AnrRow).where(AnrRow.capture_id == capture_id)
        ).one(),
        "process_kills": session.exec(
            select(func.count()).select_from(ProcessKillEventRow)
            .where(ProcessKillEventRow.capture_id == capture_id, ProcessKillEventRow.kind == "kill")
        ).one(),
        "kernel_err_events": session.exec(
            select(func.count()).select_from(KernelLogEventRow)
            .where(KernelLogEventRow.capture_id == capture_id, KernelLogEventRow.priority <= 3)
        ).one(),
        "gnss_degraded_spans": session.exec(
            select(func.count()).select_from(GnssSignalIntervalRow)
            .where(GnssSignalIntervalRow.capture_id == capture_id,
                   GnssSignalIntervalRow.quality == "poor")
        ).one(),
        "memory_samples": session.exec(
            select(func.count()).select_from(ProcessMemorySampleRow)
            .where(ProcessMemorySampleRow.capture_id == capture_id)
        ).one(),
        "selinux_denials": session.exec(
            select(func.count()).select_from(SelinuxDenialRow)
            .where(SelinuxDenialRow.capture_id == capture_id)
        ).one(),
        "selinux_enforced_denials": session.exec(
            select(func.count()).select_from(SelinuxDenialRow)
            .where(SelinuxDenialRow.capture_id == capture_id, SelinuxDenialRow.enforcing == True)  # noqa: E712
        ).one(),
        "wifi_disconnections": session.exec(
            select(func.count()).select_from(WifiEventRow)
            .where(WifiEventRow.capture_id == capture_id, WifiEventRow.kind == "disconnection")
        ).one(),
    }

    freeze_rows = session.exec(
        select(FreezeSummaryRow).where(FreezeSummaryRow.capture_id == capture_id)
    ).all()
    counts["freeze_events"] = sum(r.freeze_count for r in freeze_rows)
    counts["unfreeze_events"] = sum(r.unfreeze_count for r in freeze_rows)
    top_freeze_offenders = sorted(
        [{"package": r.package, "freezes": r.freeze_count, "unfreezes": r.unfreeze_count} for r in freeze_rows],
        key=lambda r: r["freezes"] + r["unfreezes"], reverse=True,
    )[:10]

    crash_rows = session.exec(
        select(CrashEventRow).where(CrashEventRow.capture_id == capture_id)
    ).all()
    tombstone_rows = session.exec(
        select(TombstoneRow).where(TombstoneRow.capture_id == capture_id)
    ).all()
    anr_rows = session.exec(
        select(AnrRow).where(AnrRow.capture_id == capture_id)
    ).all()
    focus_event_rows = session.exec(
        select(FocusEventRow).where(FocusEventRow.capture_id == capture_id)
    ).all()
    bt_summary_row = session.exec(
        select(BtHciSummaryRow).where(BtHciSummaryRow.capture_id == capture_id)
    ).first()
    packet_summary_row = session.exec(
        select(PacketCaptureSummaryRow).where(PacketCaptureSummaryRow.capture_id == capture_id)
    ).first()
    packet_analysis_row = session.exec(
        select(PacketAnalysisRow).where(PacketAnalysisRow.capture_id == capture_id)
    ).first()
    bt_event_rows = session.exec(
        select(BtHciEventRow).where(BtHciEventRow.capture_id == capture_id)
    ).all()
    wifi_event_rows = session.exec(
        select(WifiEventRow).where(WifiEventRow.capture_id == capture_id)
    ).all()
    process_kill_rows = session.exec(
        select(ProcessKillEventRow).where(ProcessKillEventRow.capture_id == capture_id)
    ).all()
    location_snapshot_row = session.exec(
        select(LocationSnapshotRow).where(LocationSnapshotRow.capture_id == capture_id)
    ).first()
    location_provider_rows = session.exec(
        select(LocationProviderRow).where(LocationProviderRow.capture_id == capture_id)
    ).all()
    location_usage_rows = session.exec(
        select(LocationAppUsageRow)
        .where(LocationAppUsageRow.capture_id == capture_id)
        .order_by(LocationAppUsageRow.locations.desc())
    ).all()
    gnss_interval_rows = session.exec(
        select(GnssSignalIntervalRow)
        .where(GnssSignalIntervalRow.capture_id == capture_id,
               GnssSignalIntervalRow.quality == "poor")
        .order_by(GnssSignalIntervalRow.duration_sec.desc())
    ).all()
    memory_snapshot_row = session.exec(
        select(MemorySnapshotRow).where(MemorySnapshotRow.capture_id == capture_id)
    ).first()
    memory_usage_rows = session.exec(
        select(ProcessMemoryUsageRow)
        .where(ProcessMemoryUsageRow.capture_id == capture_id)
        .order_by(ProcessMemoryUsageRow.metric, ProcessMemoryUsageRow.rank)
    ).all()
    selinux_rows = session.exec(
        select(SelinuxDenialRow).where(SelinuxDenialRow.capture_id == capture_id)
    ).all()
    battery_rows = session.exec(
        select(BatteryUidStatRow)
        .where(BatteryUidStatRow.capture_id == capture_id)
        .order_by(BatteryUidStatRow.total_mah.desc())
        .limit(15)
    ).all()

    timeline = []
    for c in crash_rows:
        timeline.append({
            "timestamp": c.timestamp, "kind": "crash", "severity": "critical",
            "label": f"{c.package or 'unknown'} crashed: {c.exception_class or 'exception'}",
            "source": _source(c.source_section, c.source_line_start, c.source_line_end),
        })
    for f in focus_event_rows:
        timeline.append({
            "timestamp": f.timestamp, "kind": "focus_event", "severity": "info",
            "label": f"{f.package}: {f.event_type}" + (f" ({f.detail})" if f.event_type == "owner_change" else ""),
            "source": _source(f.source_section, f.source_line_start, f.source_line_end),
        })
    for a in anr_rows:
        timeline.append({
            "timestamp": a.timestamp or "", "kind": "anr", "severity": "critical",
            "label": f"{a.package or 'unknown'} ANR: {a.reason or a.subject}",
            "source": None,
        })
    for t in tombstone_rows:
        timeline.append({
            "timestamp": t.timestamp or "", "kind": "native_crash", "severity": "critical",
            "label": f"{t.package or t.executable or 'unknown'} native crash: {t.signal_name or 'signal'}"
                     + (f" ({t.signal_code})" if t.signal_code else ""),
            "source": None,
        })
    for e in bt_event_rows:
        if e.kind == "disconnection_complete" or (e.status_code and e.status_code != 0):
            label = f"BT {e.kind.replace('_', ' ')}"
            if e.status_name:
                label += f": {e.status_name}"
            if e.reason_name:
                label += f" (reason: {e.reason_name})"
            timeline.append({
                "timestamp": e.timestamp, "kind": "bt_hci",
                "severity": "warning" if (e.status_code or 0) != 0 else "info",
                "label": label, "source": None,
            })
    for w in wifi_event_rows:
        if w.kind == "disconnection":
            timeline.append({
                "timestamp": w.timestamp, "kind": "wifi",
                "severity": "info" if w.locally_generated else "warning",
                "label": f"Wi-Fi disconnected from {w.ssid}: {w.reason_name}"
                         + (" (locally initiated)" if w.locally_generated else ""),
                "source": _source(w.source_section, w.source_line_start, w.source_line_end),
            })
    # Only deliberate kills go on the timeline -- processes dying is normal
    # Android lifecycle and would drown out real events.
    for k in process_kill_rows:
        if k.kind != "kill":
            continue
        timeline.append({
            "timestamp": k.timestamp, "kind": "process_kill", "severity": "warning",
            "label": f"killed {k.process}" + (f": {k.reason}" if k.reason else ""),
            "source": _source(k.source_section, k.source_line_start, k.source_line_end),
        })
    timeline.sort(key=lambda e: e["timestamp"])

    media_session_rows = session.exec(
        select(MediaSessionRow).where(MediaSessionRow.capture_id == capture_id)
    ).all()
    focus_stack_rows = session.exec(
        select(FocusStackEntryRow).where(FocusStackEntryRow.capture_id == capture_id)
    ).all()

    return {
        "capture_id": capture.id,
        "original_filename": capture.original_filename,
        "ingested_at": capture.ingested_at.isoformat(),
        "parse_warnings": [w for w in capture.parse_warnings.split("\n") if w],
        "device_info": (
            {k: v for k, v in device_info_row.__dict__.items() if not k.startswith("_") and k not in ("id", "capture_id")}
            if device_info_row else None
        ),
        "counts": counts,
        "top_freeze_offenders": top_freeze_offenders,
        "crash_events": [
            {
                "timestamp": c.timestamp, "package": c.package, "pid": c.pid,
                "exception_class": c.exception_class, "message": c.message,
                "root_cause_class": c.root_cause_class, "root_cause_message": c.root_cause_message,
                "root_cause_frame": c.root_cause_frame,
                "source": _source(c.source_section, c.source_line_start, c.source_line_end),
            } for c in crash_rows
        ],
        "tombstones": [
            {
                "filename": t.filename, "modified_at": t.modified_at, "timestamp": t.timestamp,
                "package": t.package, "executable": t.executable, "signal_name": t.signal_name,
                "signal_code": t.signal_code, "fault_addr": t.fault_addr, "top_frame": t.top_frame,
            } for t in tombstone_rows
        ],
        "anrs": [
            {
                "filename": a.filename, "timestamp": a.timestamp, "package": a.package,
                "pid": a.pid, "reason": a.reason, "subject": a.subject,
            } for a in anr_rows
        ],
        "bt_hci_summary": (
            {
                "total_packets": bt_summary_row.total_packets,
                "command_count": bt_summary_row.command_count,
                "event_count": bt_summary_row.event_count,
                "acl_data_count": bt_summary_row.acl_data_count,
                "first_timestamp": bt_summary_row.first_timestamp,
                "last_timestamp": bt_summary_row.last_timestamp,
                "event_code_counts": json.loads(bt_summary_row.event_code_counts_json),
                "notable_events": [
                    {
                        "timestamp": e.timestamp, "kind": e.kind, "status_name": e.status_name,
                        "reason_name": e.reason_name, "handle": e.handle,
                    }
                    for e in bt_event_rows
                    if e.kind == "disconnection_complete" or (e.status_code or 0) != 0
                ],
            } if bt_summary_row else None
        ),
        "packet_capture_summary": (
            {
                "format": packet_summary_row.format,
                "linktype": packet_summary_row.linktype,
                "linktype_name": packet_summary_row.linktype_name,
                "total_packets": packet_summary_row.total_packets,
                "captured_bytes": packet_summary_row.captured_bytes,
                "original_bytes": packet_summary_row.original_bytes,
                "first_timestamp": packet_summary_row.first_timestamp,
                "last_timestamp": packet_summary_row.last_timestamp,
                "truncated_packets": packet_summary_row.truncated_packets,
                "malformed_packets": packet_summary_row.malformed_packets,
            } if packet_summary_row else None
        ),
        "packet_analysis": (
            {
                "backend": packet_analysis_row.backend,
                "link_layer": packet_analysis_row.link_layer,
                "packets_analyzed": packet_analysis_row.packets_analyzed,
                "retry_count": packet_analysis_row.retry_count,
                "retry_rate_pct": packet_analysis_row.retry_rate_pct,
                "rssi_min_dbm": packet_analysis_row.rssi_min_dbm,
                "rssi_max_dbm": packet_analysis_row.rssi_max_dbm,
                "rssi_avg_dbm": packet_analysis_row.rssi_avg_dbm,
                "note": packet_analysis_row.note,
                "frame_type_breakdown": json.loads(packet_analysis_row.frame_type_breakdown_json),
                "identity_signals": json.loads(packet_analysis_row.identity_signals_json),
                "anomalies": json.loads(packet_analysis_row.anomalies_json),
            } if packet_analysis_row else None
        ),
        "process_kills": [
            {
                "timestamp": k.timestamp, "kind": k.kind, "process": k.process,
                "package": k.package, "pid": k.pid, "oom_adj": k.oom_adj,
                "reason": k.reason, "rss_kb": k.rss_kb, "proc_state": k.proc_state,
                "source": _source(k.source_section, k.source_line_start, k.source_line_end),
            } for k in process_kill_rows
        ],
        "thermal_status": (
            session.exec(
                select(ThermalSnapshotRow.overall_status_name)
                .where(ThermalSnapshotRow.capture_id == capture_id)
            ).first()
        ),
        "cpu_snapshot_present": (
            session.exec(
                select(func.count()).select_from(CpuLoadSnapshotRow)
                .where(CpuLoadSnapshotRow.capture_id == capture_id)
            ).one() > 0
        ),
        "location_snapshot": (
            {
                **{k: v for k, v in location_snapshot_row.__dict__.items()
                   if not k.startswith("_")
                   and k not in ("id", "capture_id", "source_section",
                                 "source_line_start", "source_line_end")},
                "providers": [
                    {"name": pr.name, "last_fix_provider": pr.last_fix_provider,
                     "latitude": pr.latitude, "longitude": pr.longitude,
                     "horizontal_accuracy_m": pr.horizontal_accuracy_m,
                     "satellites": pr.satellites, "mean_cn0": pr.mean_cn0}
                    for pr in location_provider_rows
                ],
                "app_usage": [
                    {"package": u.package, "provider": u.provider, "uid": u.uid,
                     "min_interval": u.min_interval, "max_interval": u.max_interval,
                     "foreground_duration": u.foreground_duration,
                     "locations": u.locations}
                    for u in location_usage_rows
                ],
                "source": _source(location_snapshot_row.source_section,
                                  location_snapshot_row.source_line_start,
                                  location_snapshot_row.source_line_end),
            } if location_snapshot_row else None
        ),
        "gnss_degraded_spans": [
            {
                "quality": iv.quality, "start_timestamp": iv.start_timestamp,
                "end_timestamp": iv.end_timestamp, "duration_sec": iv.duration_sec,
                "active_uids": iv.active_uids, "gps_active": iv.gps_active,
                "source": _source(iv.source_section, iv.source_line_start, iv.source_line_end),
            } for iv in gnss_interval_rows
        ],
        "memory_snapshot": (
            {
                **{k: v for k, v in memory_snapshot_row.__dict__.items()
                   if not k.startswith("_")
                   and k not in ("id", "capture_id", "source_section",
                                 "source_line_start", "source_line_end")},
                "top_by_rss": [
                    {"rank": u.rank, "process": u.process, "pid": u.pid,
                     "memory_kb": u.memory_kb, "state": u.state}
                    for u in memory_usage_rows if u.metric == "rss"
                ],
                "top_by_pss": [
                    {"rank": u.rank, "process": u.process, "pid": u.pid,
                     "memory_kb": u.memory_kb, "swap_kb": u.swap_kb, "state": u.state}
                    for u in memory_usage_rows if u.metric == "pss"
                ],
                "source": _source(memory_snapshot_row.source_section,
                                  memory_snapshot_row.source_line_start,
                                  memory_snapshot_row.source_line_end),
            } if memory_snapshot_row else None
        ),
        "selinux_denials": [
            {
                "timestamp": d.timestamp, "verdict": d.verdict, "permissions": d.permissions,
                "source_domain": d.source_domain, "target_type": d.target_type,
                "target_class": d.target_class, "comm": d.comm, "target_name": d.target_name,
                "app": d.app, "enforcing": d.enforcing,
                "source": _source(d.source_section, d.source_line_start, d.source_line_end),
            } for d in selinux_rows
        ],
        "wifi_events": [
            {
                "timestamp": w.timestamp, "kind": w.kind, "ssid": w.ssid, "bssid": w.bssid,
                "reason_code": w.reason_code, "reason_name": w.reason_name,
                "locally_generated": w.locally_generated, "roam": w.roam,
                "source": _source(w.source_section, w.source_line_start, w.source_line_end),
            } for w in wifi_event_rows
        ],
        "top_battery_consumers": [
            {
                "package": b.package, "uid_token": b.uid_token, "total_mah": b.total_mah,
                "fg_mah": b.fg_mah, "bg_mah": b.bg_mah, "fgs_mah": b.fgs_mah, "cached_mah": b.cached_mah,
                "components_mah": json.loads(b.components_mah_json),
                "source": _source(b.source_section, b.source_line_start, b.source_line_end),
            } for b in battery_rows
        ],
        "timeline": timeline,
        "media_sessions": [
            {
                "package": m.package, "playback_state": m.playback_state,
                "active": m.active, "position_ms": m.position_ms,
                "source": _source(m.source_section, m.source_line_start, m.source_line_end),
            } for m in media_session_rows
        ],
        "focus_stack": [
            {
                "package": e.package, "uid": e.uid, "sdk": e.sdk, "gain": e.gain,
                "source": _source(e.source_section, e.source_line_start, e.source_line_end),
            } for e in focus_stack_rows
        ],
    }


def _tag_rows(rows: list[dict], capture_id: int, original_filename: str) -> list[dict]:
    return [{**row, "capture_id": capture_id, "original_filename": original_filename} for row in rows]


def build_merged_summary(session: Session, capture_ids: list[int]) -> dict:
    """Combines build_capture_summary() across every capture in capture_ids
    into one dashboard payload -- every row is tagged with which capture it
    actually came from (capture_id + original_filename), the same principle
    already used for device-wide evidence in reasoning.py's diagnosis
    bundle. Built by reusing build_capture_summary() per capture rather than
    re-querying, so this can't drift from what the single-capture view
    already shows.

    bt_hci_summary / packet_capture_summary / packet_analysis become LISTS
    (one entry per capture that has that data) instead of a single object,
    since more than one capture can each have their own -- callers that
    only ever handled the single-capture shape need updating, this isn't
    a drop-in replacement for build_capture_summary()'s return shape.
    """
    per_capture = [s for cid in capture_ids if (s := build_capture_summary(session, cid))]
    if not per_capture:
        return {}

    merged_counts: dict[str, int] = {}
    parse_warnings: list[str] = []
    device_infos = []
    crash_events, tombstones, anrs, wifi_events = [], [], [], []
    selinux_denials: list[dict] = []
    process_kills: list[dict] = []
    top_battery_consumers, timeline, media_sessions, focus_stack = [], [], [], []
    bt_hci_summaries, packet_capture_summaries, packet_analyses = [], [], []
    freeze_offenders_by_pkg: dict[str, dict] = {}
    gnss_degraded_spans: list[dict] = []
    # Snapshot-shaped facts (one value per capture, not a count and not a
    # list) were falling out of the merged summary entirely -- found live:
    # a real capture's Overview page showed "Thermal status: n/a" for a
    # device this session had just confirmed was genuinely thermally
    # throttled (severe, 43.3C), because build_merged_summary only ever
    # merged `counts` and a handful of named lists, silently dropping
    # thermal_status/location_snapshot/memory_snapshot/cpu_snapshot_present
    # -- present in every single-capture summary, absent from every
    # device-level (merged) one, which is the view the app lands on right
    # after upload. Same bug, four fields, all fixed together below rather
    # than patched one at a time as each is separately noticed missing.
    thermal_statuses: list[tuple[int, str]] = []   # (severity rank, name) pairs
    latest_location_snapshot = latest_memory_snapshot = None
    latest_ingested_at = None
    cpu_snapshot_present = False

    for cap in per_capture:
        cid, fname = cap["capture_id"], cap["original_filename"]
        for k, v in cap["counts"].items():
            merged_counts[k] = merged_counts.get(k, 0) + v
        for w in cap["parse_warnings"]:
            parse_warnings.append(f"[{fname}] {w}")
        if cap["device_info"]:
            device_infos.append({**cap["device_info"], "capture_id": cid, "original_filename": fname})
        crash_events.extend(_tag_rows(cap["crash_events"], cid, fname))
        tombstones.extend(_tag_rows(cap["tombstones"], cid, fname))
        anrs.extend(_tag_rows(cap["anrs"], cid, fname))
        wifi_events.extend(_tag_rows(cap["wifi_events"], cid, fname))
        selinux_denials.extend(_tag_rows(cap["selinux_denials"], cid, fname))
        process_kills.extend(_tag_rows(cap["process_kills"], cid, fname))
        top_battery_consumers.extend(_tag_rows(cap["top_battery_consumers"], cid, fname))
        timeline.extend(_tag_rows(cap["timeline"], cid, fname))
        media_sessions.extend(_tag_rows(cap["media_sessions"], cid, fname))
        focus_stack.extend(_tag_rows(cap["focus_stack"], cid, fname))
        if cap["bt_hci_summary"]:
            bt_hci_summaries.append({**cap["bt_hci_summary"], "capture_id": cid, "original_filename": fname})
        if cap["packet_capture_summary"]:
            packet_capture_summaries.append({**cap["packet_capture_summary"], "capture_id": cid, "original_filename": fname})
        if cap["packet_analysis"]:
            packet_analyses.append({**cap["packet_analysis"], "capture_id": cid, "original_filename": fname})
        for o in cap["top_freeze_offenders"]:
            entry = freeze_offenders_by_pkg.setdefault(o["package"], {"package": o["package"], "freezes": 0, "unfreezes": 0})
            entry["freezes"] += o["freezes"]
            entry["unfreezes"] += o["unfreezes"]
        gnss_degraded_spans.extend(_tag_rows(cap["gnss_degraded_spans"], cid, fname))
        if cap["thermal_status"]:
            thermal_statuses.append((_THERMAL_SEVERITY_RANK.get(cap["thermal_status"], -1), cap["thermal_status"]))
        if cap["cpu_snapshot_present"]:
            cpu_snapshot_present = True
        # Snapshots are point-in-time, not summable across captures -- the
        # most recent one is what "what does this device look like right
        # now" should mean, same as picking the last-known-fix provider
        # elsewhere rather than averaging historical readings together.
        if cap["location_snapshot"] and (latest_ingested_at is None or cap["ingested_at"] > latest_ingested_at):
            latest_location_snapshot = cap["location_snapshot"]
        if cap["memory_snapshot"] and (latest_ingested_at is None or cap["ingested_at"] > latest_ingested_at):
            latest_memory_snapshot = cap["memory_snapshot"]
        if latest_ingested_at is None or cap["ingested_at"] > latest_ingested_at:
            latest_ingested_at = cap["ingested_at"]

    timeline.sort(key=lambda e: e["timestamp"])
    top_battery_consumers.sort(key=lambda b: b["total_mah"], reverse=True)
    top_freeze_offenders = sorted(
        freeze_offenders_by_pkg.values(), key=lambda o: o["freezes"] + o["unfreezes"], reverse=True
    )[:10]

    return {
        "capture_count": len(per_capture),
        "captures": [
            {"capture_id": cap["capture_id"], "original_filename": cap["original_filename"], "ingested_at": cap["ingested_at"]}
            for cap in per_capture
        ],
        "parse_warnings": parse_warnings,
        "device_infos": device_infos,
        "counts": merged_counts,
        "top_freeze_offenders": top_freeze_offenders,
        "crash_events": crash_events,
        "tombstones": tombstones,
        "anrs": anrs,
        "bt_hci_summary": bt_hci_summaries,
        "packet_capture_summary": packet_capture_summaries,
        "packet_analysis": packet_analyses,
        "wifi_events": wifi_events,
        "selinux_denials": selinux_denials,
        "process_kills": process_kills,
        "top_battery_consumers": top_battery_consumers[:15],
        "timeline": timeline,
        "media_sessions": media_sessions,
        "focus_stack": focus_stack,
        "gnss_degraded_spans": gnss_degraded_spans,
        # Worst status across all merged captures, not the newest -- a
        # device that was severely throttled once and fine every other
        # time is still a device worth flagging, unlike thermal_status's
        # single-capture meaning (that capture's own reading).
        "thermal_status": max(thermal_statuses)[1] if thermal_statuses else None,
        "location_snapshot": latest_location_snapshot,
        "memory_snapshot": latest_memory_snapshot,
        "cpu_snapshot_present": cpu_snapshot_present,
    }
