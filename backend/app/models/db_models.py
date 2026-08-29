"""Persisted structured facts. Every parsed capture's facts land here as
rows, not as a raw blob re-parsed on every query -- that's what makes
"across all captures for this device" a plain SQL query instead of a
re-parse of every uploaded zip.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    label: str = Field(index=True, unique=True)  # user-chosen identifier, e.g. serial or nickname
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Capture(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    original_filename: str
    captured_at: Optional[datetime] = None   # parsed from the bugreport's own timestamp, if known
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    parse_warnings: str = ""                 # newline-joined; empty string = clean parse


class Investigation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    label: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class InvestigationCaptureLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    investigation_id: int = Field(foreign_key="investigation.id", index=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    added_at: datetime = Field(default_factory=datetime.utcnow)


class FocusStackEntryRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    uid: int
    client_id: str
    gain: str
    flags: str
    loss: str
    notified: Optional[bool]
    limbo: Optional[bool]
    sdk: Optional[int]
    attrs: str
    is_top_of_stack: bool
    source_section: str
    source_line_start: int
    source_line_end: int


class FocusEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    event_type: str
    package: str = Field(index=True)
    uid: Optional[int]
    pid: Optional[int]
    usage: Optional[str]
    request_result: Optional[str]
    loss_code: Optional[str]
    detail: str
    source_section: str
    source_line_start: int
    source_line_end: int


class PackageFactRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    version_code: Optional[int]
    version_name: Optional[str]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    source_section: str
    source_line_start: int
    source_line_end: int


class MediaSessionRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    session_tag: str
    active: bool
    playback_state: Optional[str]
    playback_state_code: Optional[int]
    position_ms: Optional[int]
    updated_at_elapsed_ms: Optional[int]
    is_media_button_session: bool
    source_section: str
    source_line_start: int
    source_line_end: int


class ForegroundServiceRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    service_class: str
    calling_package: Optional[str] = Field(default=None, index=True)
    calling_uid: Optional[int]
    uid_state: Optional[str]
    proc_state: Optional[str]
    target_sdk_version: Optional[int]
    caller_target_sdk_version: Optional[int]
    bfgs_denied: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class DeviceInfoRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    manufacturer: Optional[str]
    model: Optional[str]
    android_release: Optional[str]
    sdk_version: Optional[int]
    build_id: Optional[str]
    build_fingerprint: Optional[str]
    security_patch: Optional[str]
    bootloader: Optional[str]
    radio: Optional[str]
    network: Optional[str]
    kernel: Optional[str]
    serial: Optional[str]
    cpu_abi: Optional[str]
    hardware: Optional[str]
    build_type: Optional[str]
    uptime: Optional[str]
    timezone: Optional[str]
    crypto_state: Optional[str]
    verified_boot_state: Optional[str]
    debuggable: Optional[bool]


class CrashEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    thread: str
    package: Optional[str] = Field(default=None, index=True)
    pid: Optional[int]
    exception_class: Optional[str]
    message: Optional[str]
    root_cause_class: Optional[str]
    root_cause_message: Optional[str]
    root_cause_frame: Optional[str]
    source_section: str
    source_line_start: int
    source_line_end: int


class TombstoneRow(SQLModel, table=True):
    """A parsed native (non-JVM) crash -- content, not just filename/mtime."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    filename: str
    modified_at: str
    timestamp: Optional[str]
    build_fingerprint: Optional[str]
    executable: Optional[str]
    cmdline: Optional[str]
    package: Optional[str] = Field(default=None, index=True)
    pid: Optional[int]
    tid: Optional[int]
    thread_name: Optional[str]
    uid: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]
    signal_code: Optional[str]
    fault_addr: Optional[str]
    abi: Optional[str]
    top_frame: Optional[str]


class AnrRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    filename: str
    timestamp: Optional[str]
    subject: str
    pid: Optional[int]
    package: Optional[str] = Field(default=None, index=True)
    reason: Optional[str]


class BtHciSummaryRow(SQLModel, table=True):
    """One row per capture: aggregate Bluetooth HCI log facts."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    total_packets: int
    command_count: int
    event_count: int
    acl_data_count: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    event_code_counts_json: str  # JSON-encoded {hex code: count}


class BtHciEventRow(SQLModel, table=True):
    """One decoded high-value HCI event (connection/disconnection/command
    complete/status) -- see app/parsers/bt_hci.py for which event types
    get per-record decoding."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    kind: str = Field(index=True)
    status_code: Optional[int]
    status_name: Optional[str]
    handle: Optional[int]
    reason_code: Optional[int]
    reason_name: Optional[str]
    opcode: Optional[int]


class PacketCaptureSummaryRow(SQLModel, table=True):
    """One row per direct packet-capture upload."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    format: str
    linktype: int
    linktype_name: str
    total_packets: int
    captured_bytes: int
    original_bytes: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    truncated_packets: int
    malformed_packets: int


class PacketAnalysisRow(SQLModel, table=True):
    """One row per direct packet-capture upload's protocol-level analysis
    (contrast with PacketCaptureSummaryRow, which is container metadata
    only). Nested lists are stored as JSON -- same pattern as
    components_mah_json on BatteryUidStatRow."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    backend: str
    packets_analyzed: int
    link_layer: str
    retry_count: Optional[int]
    retry_rate_pct: Optional[float]
    rssi_min_dbm: Optional[int]
    rssi_max_dbm: Optional[int]
    rssi_avg_dbm: Optional[float]
    note: str
    frame_type_breakdown_json: str
    identity_signals_json: str
    anomalies_json: str


class BatteryUidStatRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    uid_token: str
    uid: int
    package: Optional[str] = Field(default=None, index=True)
    total_mah: float
    fg_mah: Optional[float]
    bg_mah: Optional[float]
    fgs_mah: Optional[float]
    cached_mah: Optional[float]
    components_mah_json: str
    source_section: str
    source_line_start: int
    source_line_end: int


class CdmPairingEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    level: str
    tag: str
    kind: str = Field(index=True)
    mac_address: Optional[str] = Field(default=None, index=True)
    display_name: Optional[str]
    package_name: Optional[str] = Field(default=None, index=True)
    association_id: Optional[int]
    detail: str
    source_section: str
    source_line_start: int
    source_line_end: int


class ProcessKillEventRow(SQLModel, table=True):
    """An ActivityManager process kill or death. `kind` separates a kill
    (carries a reason) from a plain death (does not)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    kind: str = Field(index=True)
    user_id: Optional[int]
    pid: Optional[int]
    process: str
    package: Optional[str] = Field(default=None, index=True)
    oom_adj: Optional[int]
    reason: Optional[str]
    rss_kb: Optional[int]
    proc_state: Optional[int]
    source_section: str
    source_line_start: int
    source_line_end: int


class LocationSnapshotRow(SQLModel, table=True):
    """`dumpsys location` state, one row per capture. The KPI columns are
    since-boot aggregates and cannot be attributed to any time window."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    location_enabled: Optional[bool] = Field(default=None, index=True)
    gnss_hardware_model: Optional[str]
    location_failure_pct: Optional[float]
    ttff_mean_sec: Optional[float]
    ttff_stddev_sec: Optional[float]
    accuracy_mean_m: Optional[float]
    accuracy_stddev_m: Optional[float]
    cn0_mean_dbhz: Optional[float]
    cn0_threshold_dbhz: Optional[float]
    cn0_time_above_threshold_min: Optional[float]
    cn0_time_below_threshold_min: Optional[float]
    constellations: Optional[str]
    source_section: str
    source_line_start: int
    source_line_end: int


class LocationProviderRow(SQLModel, table=True):
    """One provider's last known fix. Latitude/longitude are a real physical
    position and stay local -- callers use location.redacted_coords() before
    any of this leaves the machine."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    name: str = Field(index=True)
    last_fix_provider: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    horizontal_accuracy_m: Optional[float]
    satellites: Optional[int]
    max_cn0: Optional[float]
    mean_cn0: Optional[float]
    source_section: str
    source_line_start: int
    source_line_end: int


class LocationAppUsageRow(SQLModel, table=True):
    """Per-app, per-provider location usage since boot. `locations` is the
    count actually delivered, which is what reveals an app being served
    more slowly than the rate it requested."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    provider: str = Field(index=True)
    uid: int
    package: str = Field(index=True)
    tag: Optional[str]
    min_interval: str
    max_interval: str
    total_duration: str
    foreground_duration: str
    locations: int
    source_section: str
    source_line_start: int
    source_line_end: int


class GnssSignalIntervalRow(SQLModel, table=True):
    """A span holding one GPS reception classification.

    "none" means no fix -- either still acquiring or GPS off -- and is NOT
    a reading of bad reception, so it must never be counted as degraded.
    Reception quality is also not position error: these logs never record
    the coordinates an app actually received.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    quality: str = Field(index=True)
    start_timestamp: str
    end_timestamp: str
    duration_sec: int
    active_uids: Optional[str]
    gps_active: bool
    source_section: str
    source_line_start: int
    source_line_end: int


class MemorySnapshotRow(SQLModel, table=True):
    """System-wide memory state from `dumpsys meminfo`, one row per capture.

    Every column is nullable because which lines dumpsys prints varies by
    Android version -- a NULL means the capture did not report it, which is
    a different claim from reporting zero.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    total_ram_kb: Optional[int]
    free_ram_kb: Optional[int]
    used_ram_kb: Optional[int]
    lost_ram_kb: Optional[int]
    cached_pss_kb: Optional[int]
    cached_kernel_kb: Optional[int]
    truly_free_kb: Optional[int]
    used_pss_kb: Optional[int]
    kernel_kb: Optional[int]
    zram_physical_kb: Optional[int]
    zram_in_swap_kb: Optional[int]
    total_swap_kb: Optional[int]
    status: Optional[str] = Field(default=None, index=True)
    source_section: str
    source_line_start: int
    source_line_end: int


class ProcessMemoryUsageRow(SQLModel, table=True):
    """One row of a meminfo per-process ranking. `metric` records which
    table it came from ("rss" or "pss") -- the two measure different things
    and must never be summed or compared against each other."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    metric: str = Field(index=True)
    rank: int
    process: str
    package: Optional[str] = Field(default=None, index=True)
    pid: int
    memory_kb: int
    swap_kb: Optional[int]
    state: Optional[str]
    source_section: str
    source_line_start: int
    source_line_end: int


class ProcessMemorySampleRow(SQLModel, table=True):
    """One `am_pss` sample. Repeated samples of the same pid are what make
    memory growth measurable at all.

    `pss_kb` is NULL when the build did not collect PSS (the common case on
    modern Android, where only RSS is populated) -- NULL means not
    measured, never measured-as-zero.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    pid: Optional[int] = Field(default=None, index=True)
    uid: Optional[int]
    process: str
    package: Optional[str] = Field(default=None, index=True)
    pss_kb: Optional[int]
    rss_kb: Optional[int]
    swap_pss_kb: Optional[int]
    proc_state: Optional[int]
    source_section: str
    source_line_start: int
    source_line_end: int


class SelinuxDenialRow(SQLModel, table=True):
    """One parsed SELinux AVC denial. `enforcing` distinguishes a real
    blocked operation (permissive=0) from a logged-but-allowed one
    (permissive=1); None means the log line did not say."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    verdict: str
    permissions: str                    # space-joined, e.g. "read write"
    source_context: Optional[str]
    source_domain: Optional[str] = Field(default=None, index=True)
    target_context: Optional[str]
    target_type: Optional[str] = Field(default=None, index=True)
    target_class: Optional[str]
    comm: Optional[str]
    target_name: Optional[str]
    app: Optional[str] = Field(default=None, index=True)
    enforcing: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class CompanionDeviceAssociationRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    association_id: int
    mac_address: Optional[str] = Field(default=None, index=True)
    display_name: Optional[str]
    package_name: Optional[str] = Field(default=None, index=True)
    device_profile: Optional[str]
    self_managed: Optional[bool]
    revoked: Optional[bool]
    pending: Optional[bool]
    trusted: Optional[bool]
    time_approved: Optional[str]
    last_time_connected: Optional[str]
    currently_connected: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class WifiEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    kind: str = Field(index=True)
    ssid: Optional[str]
    bssid: Optional[str]
    reason_code: Optional[int]
    reason_name: Optional[str]
    locally_generated: Optional[bool]
    roam: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class FreezeSummaryRow(SQLModel, table=True):
    """Per-package freeze/unfreeze counts for one capture. Individual
    freeze/unfreeze events aren't persisted row-by-row (a capture can have
    thousands); this is the aggregate the dashboard actually needs."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    freeze_count: int
    unfreeze_count: int
