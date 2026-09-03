"""Writes a ParsedCapture's facts into the database as rows, one capture at
a time. Nothing here re-parses raw text; it only shapes already-parsed
dataclasses into SQL rows.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime

from sqlmodel import Session, select

from app.models.db_models import (
    AnrBlockingThreadRow,
    AnrMainThreadSnapshotRow,
    AnrRow,
    CpuLoadSnapshotRow,
    KernelLogEventRow,
    ProcessCpuUsageRow,
    ThermalSensorReadingRow,
    ThermalSnapshotRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    Capture,
    CdmPairingEventRow,
    CompanionDeviceAssociationRow,
    CrashEventRow,
    Device,
    DeviceInfoRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    Investigation,
    InvestigationCaptureLink,
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
from app.parsers.base import DeviceInfo, ParsedCapture


# Hardware identity compared at persist time so two physical devices cannot
# silently share a device_label (and then corroborate across captures).
# Parsers stay ground truth; this is ingestion identity, not narration.
DEVICE_IDENTITY_FIELDS = ("serial", "build_fingerprint", "manufacturer", "model")

UNVERIFIED_DEVICE_IDENTITY_WARNING = (
    "Cannot verify device identity for this label: capture has no serial, "
    "build_fingerprint, manufacturer, or model to compare; persisted anyway."
)


class DeviceIdentityMismatchError(Exception):
    """Refuse persist when a device_label already holds different hardware."""

    def __init__(self, device_label: str, mismatched_fields: list[str]):
        self.device_label = device_label
        self.mismatched_fields = list(mismatched_fields)
        self.error = "device_identity_mismatch"
        message = (
            "This capture's hardware identity does not match captures already "
            "stored under this device label "
            f"(mismatched fields: {', '.join(self.mismatched_fields)}). "
            "Upload under a different label."
        )
        super().__init__(message)

    def as_api_detail(self) -> dict:
        # Field names only -- never echo serials or fingerprints.
        return {
            "error": self.error,
            "message": str(self),
            "mismatched_fields": self.mismatched_fields,
            "device_label": self.device_label,
        }


def _identity_values(info: DeviceInfo | DeviceInfoRow | None) -> dict[str, str]:
    if info is None:
        return {}
    values: dict[str, str] = {}
    for field in DEVICE_IDENTITY_FIELDS:
        raw = getattr(info, field, None)
        if isinstance(raw, str):
            stripped = raw.strip()
            if stripped:
                values[field] = stripped
    return values


def check_device_label_identity(session: Session, device_label: str, parsed: ParsedCapture) -> None:
    """Compare incoming hardware identity against captures already on this label.

    Mismatch of any overlapping identity field refuses persist. Incoming
    capture with no comparable identity warns and still persists, because
    blocking would drop partial dumps. A new label has nothing to compare.
    """
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        return

    existing_capture_ids = session.exec(
        select(Capture.id).where(Capture.device_id == device.id)
    ).all()
    if not existing_capture_ids:
        return

    incoming = _identity_values(parsed.device_info)
    if not incoming:
        # PC-ingestion-003: cannot compare; persist with a visible warning.
        parsed.parse_warnings.append(UNVERIFIED_DEVICE_IDENTITY_WARNING)
        return

    existing_rows = session.exec(
        select(DeviceInfoRow).where(DeviceInfoRow.capture_id.in_(existing_capture_ids))
    ).all()

    mismatched: list[str] = []
    for field in DEVICE_IDENTITY_FIELDS:
        incoming_value = incoming.get(field)
        if not incoming_value:
            continue
        for row in existing_rows:
            existing_value = _identity_values(row).get(field)
            if existing_value and existing_value != incoming_value:
                mismatched.append(field)
                break

    if mismatched:
        raise DeviceIdentityMismatchError(device_label, mismatched)


def get_or_create_device(session: Session, device_label: str) -> Device:
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        device = Device(label=device_label)
        session.add(device)
        session.commit()
        session.refresh(device)
    return device


def get_or_create_investigation(session: Session, investigation_label: str) -> Investigation:
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        investigation = Investigation(label=investigation_label)
        session.add(investigation)
        session.commit()
        session.refresh(investigation)
    return investigation


def persist_capture(
    session: Session,
    device_label: str,
    original_filename: str,
    parsed: ParsedCapture,
    captured_at: datetime | None = None,
    investigation_label: str | None = None,
) -> Capture:
    check_device_label_identity(session, device_label, parsed)
    device = get_or_create_device(session, device_label)

    capture = Capture(
        device_id=device.id,
        original_filename=original_filename,
        captured_at=captured_at,
        parse_warnings="\n".join(parsed.parse_warnings),
    )
    session.add(capture)
    session.commit()
    session.refresh(capture)

    if investigation_label:
        investigation = get_or_create_investigation(session, investigation_label)
        session.add(InvestigationCaptureLink(
            investigation_id=investigation.id,
            capture_id=capture.id,
        ))

    for e in parsed.focus_stack:
        session.add(FocusStackEntryRow(
            capture_id=capture.id,
            package=e.package, uid=e.uid, client_id=e.client_id,
            gain=e.gain, flags=e.flags, loss=e.loss,
            notified=e.notified, limbo=e.limbo, sdk=e.sdk, attrs=e.attrs,
            is_top_of_stack=e.is_top_of_stack,
            source_section=e.source_ref.section,
            source_line_start=e.source_ref.line_start,
            source_line_end=e.source_ref.line_end,
        ))

    for e in parsed.focus_events:
        session.add(FocusEventRow(
            capture_id=capture.id,
            timestamp=e.timestamp, event_type=e.event_type, package=e.package,
            uid=e.uid, pid=e.pid, usage=e.usage,
            request_result=e.request_result, loss_code=e.loss_code, detail=e.detail,
            source_section=e.source_ref.section,
            source_line_start=e.source_ref.line_start,
            source_line_end=e.source_ref.line_end,
        ))

    for pkg, p in parsed.packages.items():
        session.add(PackageFactRow(
            capture_id=capture.id,
            package=pkg, version_code=p.version_code, version_name=p.version_name,
            min_sdk=p.min_sdk, target_sdk=p.target_sdk,
            source_section=p.source_ref.section,
            source_line_start=p.source_ref.line_start,
            source_line_end=p.source_ref.line_end,
        ))

    for m in parsed.media_sessions:
        session.add(MediaSessionRow(
            capture_id=capture.id,
            package=m.package, session_tag=m.session_tag, active=m.active,
            playback_state=m.playback_state, playback_state_code=m.playback_state_code,
            position_ms=m.position_ms, updated_at_elapsed_ms=m.updated_at_elapsed_ms,
            is_media_button_session=m.is_media_button_session,
            source_section=m.source_ref.section,
            source_line_start=m.source_ref.line_start,
            source_line_end=m.source_ref.line_end,
        ))

    for f in parsed.foreground_services:
        session.add(ForegroundServiceRow(
            capture_id=capture.id,
            package=f.package, service_class=f.service_class,
            calling_package=f.calling_package, calling_uid=f.calling_uid,
            uid_state=f.uid_state, proc_state=f.proc_state,
            target_sdk_version=f.target_sdk_version,
            caller_target_sdk_version=f.caller_target_sdk_version,
            bfgs_denied=f.bfgs_denied,
            source_section=f.source_ref.section,
            source_line_start=f.source_ref.line_start,
            source_line_end=f.source_ref.line_end,
        ))

    if parsed.device_info is not None:
        di = parsed.device_info
        session.add(DeviceInfoRow(
            capture_id=capture.id,
            manufacturer=di.manufacturer, model=di.model,
            android_release=di.android_release, sdk_version=di.sdk_version,
            build_id=di.build_id, build_fingerprint=di.build_fingerprint,
            security_patch=di.security_patch, bootloader=di.bootloader,
            radio=di.radio, network=di.network, kernel=di.kernel,
            serial=di.serial, cpu_abi=di.cpu_abi, hardware=di.hardware,
            build_type=di.build_type, uptime=di.uptime, timezone=di.timezone,
            crypto_state=di.crypto_state, verified_boot_state=di.verified_boot_state,
            debuggable=di.debuggable,
        ))

    for c in parsed.crash_events:
        session.add(CrashEventRow(
            capture_id=capture.id,
            timestamp=c.timestamp, thread=c.thread, package=c.package, pid=c.pid,
            exception_class=c.exception_class, message=c.message,
            root_cause_class=c.root_cause_class, root_cause_message=c.root_cause_message,
            root_cause_frame=c.root_cause_frame,
            source_section=c.source_ref.section,
            source_line_start=c.source_ref.line_start,
            source_line_end=c.source_ref.line_end,
        ))

    for t in parsed.tombstones:
        session.add(TombstoneRow(
            capture_id=capture.id, filename=t.filename, modified_at=t.modified_at,
            timestamp=t.timestamp, build_fingerprint=t.build_fingerprint,
            executable=t.executable, cmdline=t.cmdline, package=t.package,
            pid=t.pid, tid=t.tid, thread_name=t.thread_name, uid=t.uid,
            signal_number=t.signal_number, signal_name=t.signal_name,
            signal_code=t.signal_code, fault_addr=t.fault_addr, abi=t.abi,
            top_frame=t.top_frame,
        ))

    for a in parsed.anrs:
        session.add(AnrRow(
            capture_id=capture.id, filename=a.filename, timestamp=a.timestamp,
            subject=a.subject, pid=a.pid, package=a.package, reason=a.reason,
            timeout_ms=a.timeout_ms, rss_kb=a.rss_kb,
        ))
        for bt in a.blocking_threads:
            session.add(AnrBlockingThreadRow(
                capture_id=capture.id, anr_filename=a.filename,
                thread_id=bt.thread_id, from_pid=bt.from_pid, to_pid=bt.to_pid,
                elapsed_ms=bt.elapsed_ms,
                source_section=bt.source_ref.section,
                source_line_start=bt.source_ref.line_start,
                source_line_end=bt.source_ref.line_end,
            ))

    for snap in parsed.anr_main_thread_snapshots:
        session.add(AnrMainThreadSnapshotRow(
            capture_id=capture.id, pid=snap.pid, process=snap.process,
            state=snap.state, held_mutexes=snap.held_mutexes,
            top_frames_json=json.dumps(snap.top_frames),
            source_section=snap.source_ref.section,
            source_line_start=snap.source_ref.line_start,
            source_line_end=snap.source_ref.line_end,
        ))

    for ev in parsed.kernel_log_events:
        session.add(KernelLogEventRow(
            capture_id=capture.id, boot_relative_sec=ev.boot_relative_sec,
            priority=ev.priority, priority_name=ev.priority_name, thread=ev.thread,
            message=ev.message, is_panic_family=ev.is_panic_family,
            source_section=ev.source_ref.section,
            source_line_start=ev.source_ref.line_start,
            source_line_end=ev.source_ref.line_end,
        ))

    th = parsed.thermal_snapshot
    if th is not None:
        session.add(ThermalSnapshotRow(
            capture_id=capture.id, overall_status_code=th.overall_status_code,
            overall_status_name=th.overall_status_name,
            source_section=th.source_ref.section,
            source_line_start=th.source_ref.line_start,
            source_line_end=th.source_ref.line_end,
        ))
        for sensor in th.sensors:
            session.add(ThermalSensorReadingRow(
                capture_id=capture.id, name=sensor.name, value_c=sensor.value_c,
                type_code=sensor.type_code, type_name=sensor.type_name,
                status_code=sensor.status_code, status_name=sensor.status_name,
            ))

    cpu = parsed.cpu_load_snapshot
    if cpu is not None:
        session.add(CpuLoadSnapshotRow(
            capture_id=capture.id, total_pct=cpu.total_pct, user_pct=cpu.user_pct,
            sys_pct=cpu.sys_pct, idle_pct=cpu.idle_pct, iowait_pct=cpu.iowait_pct,
            irq_pct=cpu.irq_pct, softirq_pct=cpu.softirq_pct,
            threads_total=cpu.threads_total, threads_running=cpu.threads_running,
            source_section=cpu.source_ref.section,
            source_line_start=cpu.source_ref.line_start,
            source_line_end=cpu.source_ref.line_end,
        ))
        for proc in cpu.top_processes:
            session.add(ProcessCpuUsageRow(
                capture_id=capture.id, pid=proc.pid, tid=proc.tid, user=proc.user,
                cpu_pct=proc.cpu_pct, state=proc.state, command=proc.command,
            ))

    if parsed.bt_hci_summary is not None:
        s = parsed.bt_hci_summary
        session.add(BtHciSummaryRow(
            capture_id=capture.id, total_packets=s.total_packets,
            command_count=s.command_count, event_count=s.event_count,
            acl_data_count=s.acl_data_count, first_timestamp=s.first_timestamp,
            last_timestamp=s.last_timestamp,
            event_code_counts_json=json.dumps(s.event_code_counts),
        ))
        for e in s.events:
            session.add(BtHciEventRow(
                capture_id=capture.id, timestamp=e.timestamp, kind=e.kind,
                status_code=e.status_code, status_name=e.status_name,
                handle=e.handle, reason_code=e.reason_code, reason_name=e.reason_name,
                opcode=e.opcode,
            ))

    if parsed.packet_capture_summary is not None:
        p = parsed.packet_capture_summary
        session.add(PacketCaptureSummaryRow(
            capture_id=capture.id, format=p.format, linktype=p.linktype,
            linktype_name=p.linktype_name, total_packets=p.total_packets,
            captured_bytes=p.captured_bytes, original_bytes=p.original_bytes,
            first_timestamp=p.first_timestamp, last_timestamp=p.last_timestamp,
            truncated_packets=p.truncated_packets, malformed_packets=p.malformed_packets,
        ))

    if parsed.packet_analysis is not None:
        pa = parsed.packet_analysis
        session.add(PacketAnalysisRow(
            capture_id=capture.id, backend=pa.backend, packets_analyzed=pa.packets_analyzed,
            link_layer=pa.link_layer, retry_count=pa.retry_count, retry_rate_pct=pa.retry_rate_pct,
            rssi_min_dbm=pa.rssi_min_dbm, rssi_max_dbm=pa.rssi_max_dbm, rssi_avg_dbm=pa.rssi_avg_dbm,
            note=pa.note,
            frame_type_breakdown_json=json.dumps([{"label": f.label, "count": f.count} for f in pa.frame_type_breakdown]),
            identity_signals_json=json.dumps([{"kind": s.kind, "value": s.value, "count": s.count} for s in pa.identity_signals]),
            anomalies_json=json.dumps([
                {"timestamp": a.timestamp, "kind": a.kind, "detail": a.detail, "mac_or_ip": a.mac_or_ip}
                for a in pa.anomalies
            ]),
        ))

    for w in parsed.wifi_events:
        session.add(WifiEventRow(
            capture_id=capture.id, timestamp=w.timestamp, kind=w.kind,
            ssid=w.ssid, bssid=w.bssid, reason_code=w.reason_code, reason_name=w.reason_name,
            locally_generated=w.locally_generated, roam=w.roam,
            source_section=w.source_ref.section,
            source_line_start=w.source_ref.line_start,
            source_line_end=w.source_ref.line_end,
        ))

    for b in parsed.battery_uid_stats:
        session.add(BatteryUidStatRow(
            capture_id=capture.id, uid_token=b.uid_token, uid=b.uid, package=b.package,
            total_mah=b.total_mah, fg_mah=b.fg_mah, bg_mah=b.bg_mah,
            fgs_mah=b.fgs_mah, cached_mah=b.cached_mah,
            components_mah_json=json.dumps(b.components_mah),
            source_section=b.source_ref.section,
            source_line_start=b.source_ref.line_start,
            source_line_end=b.source_ref.line_end,
        ))

    for e in parsed.cdm_pairing_events:
        session.add(CdmPairingEventRow(
            capture_id=capture.id, timestamp=e.timestamp, level=e.level, tag=e.tag,
            kind=e.kind, mac_address=e.mac_address, display_name=e.display_name,
            package_name=e.package_name, association_id=e.association_id, detail=e.detail,
            source_section=e.source_ref.section,
            source_line_start=e.source_ref.line_start,
            source_line_end=e.source_ref.line_end,
        ))

    for k in parsed.process_kills:
        session.add(ProcessKillEventRow(
            capture_id=capture.id, timestamp=k.timestamp, kind=k.kind,
            user_id=k.user_id, pid=k.pid, process=k.process, package=k.package,
            oom_adj=k.oom_adj, reason=k.reason, rss_kb=k.rss_kb, proc_state=k.proc_state,
            source_section=k.source_ref.section,
            source_line_start=k.source_ref.line_start,
            source_line_end=k.source_ref.line_end,
        ))

    loc = parsed.location_snapshot
    if loc is not None:
        k = loc.kpi
        session.add(LocationSnapshotRow(
            capture_id=capture.id,
            location_enabled=loc.location_enabled,
            gnss_hardware_model=loc.gnss_hardware_model,
            location_failure_pct=k.location_failure_pct if k else None,
            ttff_mean_sec=k.ttff_mean_sec if k else None,
            ttff_stddev_sec=k.ttff_stddev_sec if k else None,
            accuracy_mean_m=k.accuracy_mean_m if k else None,
            accuracy_stddev_m=k.accuracy_stddev_m if k else None,
            cn0_mean_dbhz=k.cn0_mean_dbhz if k else None,
            cn0_threshold_dbhz=k.cn0_threshold_dbhz if k else None,
            cn0_time_above_threshold_min=k.cn0_time_above_threshold_min if k else None,
            cn0_time_below_threshold_min=k.cn0_time_below_threshold_min if k else None,
            constellations=k.constellations if k else None,
            source_section=loc.source_ref.section,
            source_line_start=loc.source_ref.line_start,
            source_line_end=loc.source_ref.line_end,
        ))
        for pr in loc.providers:
            session.add(LocationProviderRow(
                capture_id=capture.id, name=pr.name, last_fix_provider=pr.last_fix_provider,
                latitude=pr.latitude, longitude=pr.longitude,
                horizontal_accuracy_m=pr.horizontal_accuracy_m, satellites=pr.satellites,
                max_cn0=pr.max_cn0, mean_cn0=pr.mean_cn0,
                source_section=pr.source_ref.section,
                source_line_start=pr.source_ref.line_start,
                source_line_end=pr.source_ref.line_end,
            ))
        for u in loc.app_usage:
            session.add(LocationAppUsageRow(
                capture_id=capture.id, provider=u.provider, uid=u.uid, package=u.package,
                tag=u.tag, min_interval=u.min_interval, max_interval=u.max_interval,
                total_duration=u.total_duration, foreground_duration=u.foreground_duration,
                locations=u.locations,
                source_section=u.source_ref.section,
                source_line_start=u.source_ref.line_start,
                source_line_end=u.source_ref.line_end,
            ))

    for iv in parsed.gnss_signal_intervals:
        session.add(GnssSignalIntervalRow(
            capture_id=capture.id, quality=iv.quality,
            start_timestamp=iv.start_timestamp, end_timestamp=iv.end_timestamp,
            duration_sec=iv.duration_sec, active_uids=iv.active_uids, gps_active=iv.gps_active,
            source_section=iv.source_ref.section,
            source_line_start=iv.source_ref.line_start,
            source_line_end=iv.source_ref.line_end,
        ))

    snap = parsed.memory_snapshot
    if snap is not None:
        session.add(MemorySnapshotRow(
            capture_id=capture.id,
            total_ram_kb=snap.total_ram_kb, free_ram_kb=snap.free_ram_kb,
            used_ram_kb=snap.used_ram_kb, lost_ram_kb=snap.lost_ram_kb,
            cached_pss_kb=snap.cached_pss_kb, cached_kernel_kb=snap.cached_kernel_kb,
            truly_free_kb=snap.truly_free_kb, used_pss_kb=snap.used_pss_kb,
            kernel_kb=snap.kernel_kb, zram_physical_kb=snap.zram_physical_kb,
            zram_in_swap_kb=snap.zram_in_swap_kb, total_swap_kb=snap.total_swap_kb,
            status=snap.status,
            source_section=snap.source_ref.section,
            source_line_start=snap.source_ref.line_start,
            source_line_end=snap.source_ref.line_end,
        ))
        # `rank` is stored rather than derived later: the tables arrive
        # already sorted by the device, and re-sorting on memory_kb after a
        # round-trip would silently reorder ties.
        for metric, rows in (("rss", snap.top_by_rss), ("pss", snap.top_by_pss)):
            for rank, u in enumerate(rows, start=1):
                session.add(ProcessMemoryUsageRow(
                    capture_id=capture.id, metric=metric, rank=rank,
                    process=u.process, package=u.process.split(":")[0],
                    pid=u.pid, memory_kb=u.memory_kb, swap_kb=u.swap_kb, state=u.state,
                    source_section=u.source_ref.section,
                    source_line_start=u.source_ref.line_start,
                    source_line_end=u.source_ref.line_end,
                ))

    for m in parsed.memory_samples:
        session.add(ProcessMemorySampleRow(
            capture_id=capture.id, timestamp=m.timestamp, pid=m.pid, uid=m.uid,
            process=m.process, package=m.package, pss_kb=m.pss_kb, rss_kb=m.rss_kb,
            swap_pss_kb=m.swap_pss_kb, proc_state=m.proc_state,
            source_section=m.source_ref.section,
            source_line_start=m.source_ref.line_start,
            source_line_end=m.source_ref.line_end,
        ))

    for d in parsed.selinux_denials:
        session.add(SelinuxDenialRow(
            capture_id=capture.id, timestamp=d.timestamp, verdict=d.verdict,
            permissions=" ".join(d.permissions),
            source_context=d.source_context, source_domain=d.source_domain,
            target_context=d.target_context, target_type=d.target_type,
            target_class=d.target_class, comm=d.comm, target_name=d.target_name,
            app=d.app, enforcing=d.enforcing,
            source_section=d.source_ref.section,
            source_line_start=d.source_ref.line_start,
            source_line_end=d.source_ref.line_end,
        ))

    for a in parsed.companion_device_associations:
        session.add(CompanionDeviceAssociationRow(
            capture_id=capture.id, association_id=a.association_id, mac_address=a.mac_address,
            display_name=a.display_name, package_name=a.package_name, device_profile=a.device_profile,
            self_managed=a.self_managed, revoked=a.revoked, pending=a.pending, trusted=a.trusted,
            time_approved=a.time_approved, last_time_connected=a.last_time_connected,
            currently_connected=a.currently_connected,
            source_section=a.source_ref.section,
            source_line_start=a.source_ref.line_start,
            source_line_end=a.source_ref.line_end,
        ))

    freeze_counts: Counter = Counter()
    unfreeze_counts: Counter = Counter()
    for e in parsed.freeze_events:
        (freeze_counts if e.event_type == "freeze" else unfreeze_counts)[e.package] += 1
    for pkg in set(freeze_counts) | set(unfreeze_counts):
        session.add(FreezeSummaryRow(
            capture_id=capture.id, package=pkg,
            freeze_count=freeze_counts.get(pkg, 0),
            unfreeze_count=unfreeze_counts.get(pkg, 0),
        ))

    session.commit()
    session.refresh(capture)
    return capture
