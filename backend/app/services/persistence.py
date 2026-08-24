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
    AnrRow,
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
    MemorySnapshotRow,
    ProcessKillEventRow,
    ProcessMemorySampleRow,
    ProcessMemoryUsageRow,
    SelinuxDenialRow,
    TombstoneRow,
    WifiEventRow,
)
from app.parsers.base import ParsedCapture


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
