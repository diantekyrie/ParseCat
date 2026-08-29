"""Shared types for parsed, structured facts pulled out of a bugreport.

Every fact carries a SourceRef so a diagnosis can cite the exact lines it
came from instead of asserting things the LLM can't point back to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SourceRef:
    """Points back at the exact place a fact was read from."""

    section: str          # e.g. "audio", "package", "media_session", "activity"
    line_start: int       # 1-indexed, absolute line number in the raw bugreport txt
    line_end: int

    def as_dict(self) -> dict:
        return {"section": self.section, "line_start": self.line_start, "line_end": self.line_end}


@dataclass
class FocusStackEntry:
    """One entry in the live 'Audio Focus stack entries' snapshot."""

    package: str
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
    source_ref: SourceRef


@dataclass
class FocusEvent:
    """One line from the MediaFocusControl event history."""

    timestamp: str          # raw "MM-DD HH:MM:SS:mmm" as printed, device-local
    event_type: str         # "request" | "abandon" | "owner_change"
    package: str
    uid: Optional[int]
    pid: Optional[int]
    usage: Optional[str]
    request_result: Optional[str]   # e.g. "1" (GRANTED) for request events
    loss_code: Optional[str]        # e.g. "-2" for handleLoss events
    detail: str                     # trailing free text (e.g. "handleLoss", "died")
    source_ref: SourceRef


@dataclass
class PackageFacts:
    package: str
    version_code: Optional[int]
    version_name: Optional[str]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    app_id: Optional[int]   # from "appId=NNNNN" -- lets other UID-keyed
                             # sections (e.g. battery stats) be attributed
                             # back to a package: uid = userId*100000 + appId
    source_ref: SourceRef


@dataclass
class MediaSessionFacts:
    package: str
    session_tag: str
    active: bool
    playback_state: Optional[str]        # e.g. "PLAYING", "PAUSED"
    playback_state_code: Optional[int]
    position_ms: Optional[int]
    updated_at_elapsed_ms: Optional[int]  # SystemClock.elapsedRealtime() at last update
    is_media_button_session: bool
    source_ref: SourceRef


@dataclass
class ForegroundServiceFacts:
    package: str                      # package hosting the service
    service_class: str
    calling_package: Optional[str]    # who bound/started it (c: field)
    calling_uid: Optional[int]
    uid_state: Optional[str]          # e.g. "TOP", "CACC"
    proc_state: Optional[str]         # e.g. "PROC_STATE_TOP"
    target_sdk_version: Optional[int]
    caller_target_sdk_version: Optional[int]
    bfgs_denied: Optional[bool]
    source_ref: SourceRef


@dataclass
class ProcessFreezeEvent:
    """One `ActivityManager: freezing <pid> <process>` or
    `ActivityManager: sync unfroze <pid> <process> for <ms>` logcat line.
    The cached-process freezer is Android's mechanism for pausing
    background-process CPU/binder activity; a process stuck frozen (or
    thrashing freeze/unfreeze) is a common root cause of "app didn't
    respond to X" reports that isn't visible in any dumpsys snapshot.
    """

    timestamp: str                 # "MM-DD HH:MM:SS.mmm", device-local
    event_type: str                # "freeze" | "unfreeze"
    pid: int
    process: str                   # full process name, e.g. "com.android.vending:background"
    package: str                   # process name up to the first ':'
    # The trailing "for N" on an unfreeze line. N takes only a handful of
    # small values (observed: 1,3,4,6,7,10,19) -- that's a reason-code enum
    # from AOSP's CachedAppOptimizer, not a duration in ms. Reported as the
    # raw code rather than guessing/asserting a unit we haven't confirmed.
    unfreeze_reason_code: Optional[int]
    source_ref: SourceRef


@dataclass
class CrashEvent:
    """A Java `FATAL EXCEPTION` crash, parsed from the system log's
    AndroidRuntime lines:

        E AndroidRuntime: FATAL EXCEPTION: <thread>
        E AndroidRuntime: Process: <package>, PID: <pid>
        E AndroidRuntime: <ExceptionClass>: <message>
    """

    timestamp: str
    thread: str
    package: Optional[str]
    pid: Optional[int]
    exception_class: Optional[str]
    message: Optional[str]
    # The DEEPEST "Caused by:" exception in the chain -- usually the actual
    # root cause (e.g. a top-level "Unable to create application" wrapping
    # a third-party SDK's "Caused by: RuntimeException: 25"). None if the
    # crash had no "Caused by:" chain.
    root_cause_class: Optional[str]
    root_cause_message: Optional[str]
    root_cause_frame: Optional[str]  # first stack frame under the root cause, e.g. "com.foo.Bar.baz(Bar.java:69)"
    source_ref: SourceRef


@dataclass
class TombstoneFacts:
    """Parsed contents of one plain-text tombstone file
    (FS/data/tombstones/tombstone_NN) -- a native (non-JVM) crash dump.
    The `.pb` protobuf sibling of each tombstone is not parsed; the
    plain-text version carries the same facts in a directly-parseable form.
    """

    filename: str
    modified_at: str                   # as reported by the zip entry, device-local
    timestamp: Optional[str]           # device-local, as printed in the tombstone's own header
    build_fingerprint: Optional[str]
    executable: Optional[str]
    cmdline: Optional[str]
    package: Optional[str]             # derived from cmdline; None for native binaries
    pid: Optional[int]
    tid: Optional[int]
    thread_name: Optional[str]
    uid: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]         # e.g. "SIGSEGV"
    signal_code: Optional[str]         # e.g. "SEGV_MAPERR"
    fault_addr: Optional[str]
    abi: Optional[str]
    top_frame: Optional[str]           # first #00 backtrace line -- the crashing frame


@dataclass
class DeviceInfo:
    """Static device/build facts pulled from the bugreport's plain-text
    preamble and its `getprop` (SYSTEM PROPERTIES) dump. Every field is
    Optional -- a bugreport from a different OS version/vendor build may
    not print all of these, and an absent field is reported as unknown
    rather than guessed.
    """

    manufacturer: Optional[str] = None
    model: Optional[str] = None
    android_release: Optional[str] = None
    sdk_version: Optional[int] = None
    build_id: Optional[str] = None
    build_fingerprint: Optional[str] = None
    security_patch: Optional[str] = None
    bootloader: Optional[str] = None
    radio: Optional[str] = None
    network: Optional[str] = None
    kernel: Optional[str] = None
    serial: Optional[str] = None
    cpu_abi: Optional[str] = None
    hardware: Optional[str] = None
    build_type: Optional[str] = None
    uptime: Optional[str] = None
    timezone: Optional[str] = None
    crypto_state: Optional[str] = None
    verified_boot_state: Optional[str] = None
    debuggable: Optional[bool] = None


@dataclass
class AnrFacts:
    """Parsed contents of one ANR (Application Not Responding) trace file
    (FS/data/anr/anr_<timestamp> inside the bugreport zip -- a separate
    file, not text inside the flattened bugreport txt).

    The `Subject:` header line always has the shape:
        Process ProcessRecord{<hash> <pid>:<package>/<user>} <reason>
    e.g. "Process ProcessRecord{2e7636c 16041:com.disney.wdpro.dlr/u0a335}
    failed to complete startup" -- pid, package, and the failure reason are
    all pulled from this one line, which is always present.
    """

    filename: str
    timestamp: Optional[str]   # parsed from the filename, e.g. "2026-07-22-17-38-38-800"
    subject: str                # full raw Subject: line
    pid: Optional[int]
    package: Optional[str]
    reason: Optional[str]       # e.g. "failed to complete startup", "Input dispatching timed out"


@dataclass
class BtHciEvent:
    """One decoded HCI event/command-status/command-complete record from
    the device's `btsnoop`-format Bluetooth HCI log
    (FS/data/misc/bluetooth/logs/btsnooz_hci.log -- despite the filename,
    verified against real bytes to be the classic btsnoop binary format,
    not the compressed bugreport-inline "btsnooz" variant). Only the
    diagnostically load-bearing event types are decoded per-record
    (connection/disconnection complete, command complete/status, LE
    connection complete); everything else is counted in
    BtHciSummary.event_code_counts without per-record decoding.
    """

    timestamp: str          # ISO-ish UTC, converted from the btsnoop 64-bit epoch
    kind: str                # "disconnection_complete" | "connection_complete" |
                              # "command_complete" | "command_status" |
                              # "le_connection_complete"
    status_code: Optional[int]
    status_name: Optional[str]     # human label from the HCI status code table, or None if unmapped
    handle: Optional[int]
    reason_code: Optional[int]      # disconnection reason, same code table as status
    reason_name: Optional[str]
    opcode: Optional[int]           # command opcode, for command_complete/command_status


@dataclass
class BtHciSummary:
    """Aggregate facts from one capture's Bluetooth HCI log."""

    total_packets: int
    command_count: int
    event_count: int
    acl_data_count: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    event_code_counts: dict          # {hex event code string: count}
    events: list[BtHciEvent] = field(default_factory=list)  # only the decoded high-value ones


@dataclass
class PacketCaptureSummary:
    """Generic packet-capture file facts for direct `.pcap` uploads.

    This is intentionally capture-level metadata rather than packet-by-packet
    persistence: enough to confirm the file was recognized, bounded, and
    timestamped before adding protocol-specific decoders.
    """

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


@dataclass
class PacketFrameTypeStat:
    """One row of a frame-type / protocol breakdown -- e.g. ("Beacon", 17261)
    for 802.11, or ("DNS", 42) for an Ethernet/IP capture."""

    label: str
    count: int


@dataclass
class PacketIdentitySignal:
    """One identifying value observed in the capture -- an SSID, BSSID, DNS
    query name, or similar -- with how many packets carried it."""

    kind: str    # "ssid" | "bssid" | "dns_query"
    value: str
    count: int


@dataclass
class PacketAnomalyEvent:
    """One notable event found in the capture -- a deauth/disassoc frame,
    a TCP reset, etc. Not exhaustive; see PacketAnalysis.note for what this
    backend does and doesn't detect."""

    timestamp: Optional[str]
    kind: str    # "deauthentication" | "disassociation" | "tcp_reset"
    detail: str
    mac_or_ip: Optional[str] = None


@dataclass
class PacketAnalysis:
    """Real protocol-level analysis of a packet capture -- contrast with
    PacketCaptureSummary, which is container-level metadata only (packet
    count/bytes/time range, no look inside a single packet).

    Two backends can produce this, and `backend` says which one actually
    ran so the LLM-facing bundle can be honest about relative completeness
    (see reasoning.py) rather than presenting both as equally authoritative:

    - "tshark": full Wireshark dissection via a `tshark` subprocess. Not
      live-verified in THIS codebase's dev/test environment (tshark isn't
      installed there) -- verify against a real capture the first time
      this path actually runs somewhere tshark is present, the same way
      every other parser here was verified against real bytes.
    - "fallback": a from-scratch parser with no external tool or library
      dissection dependency, written after finding that scapy's own
      general-purpose packet dissection is far too slow for a real
      monitor-mode capture (297,262 packets took >120s to even construct
      RadioTap objects one at a time; the hand-rolled radiotap/802.11
      header parser used instead does the same file in ~2s). Verified
      byte-for-byte against scapy's own RadioTap.dBm_AntSignal decoding
      on a real capture (0 mismatches across 3000 packets) before being
      trusted for the full run. Retransmission/TCP-stream analysis is
      NOT attempted in this backend -- that needs tshark's own
      stream-tracking, so retransmission counts are tshark-only; see
      `note` for what's missing on a given result.
    """

    backend: str
    packets_analyzed: int
    link_layer: str    # "802.11" | "ethernet" | "unknown"
    frame_type_breakdown: list[PacketFrameTypeStat]
    retry_count: Optional[int]          # 802.11 only
    retry_rate_pct: Optional[float]     # 802.11 only
    rssi_min_dbm: Optional[int]
    rssi_max_dbm: Optional[int]
    rssi_avg_dbm: Optional[float]
    identity_signals: list[PacketIdentitySignal]
    anomalies: list[PacketAnomalyEvent]
    note: str


@dataclass
class WifiEvent:
    """One decoded event from `DUMP OF SERVICE wifi` -> WifiController's
    state-machine transition log (`rec[N]: time=... what=EVENT_NAME ...`).
    Only the diagnostically load-bearing event types are decoded
    (disconnection with 802.11 reason code, BSSID association/roam);
    the state machine log has many other "what=" event types not parsed
    here (e.g. CMD_UPDATE_AP_CAPABILITY, screen state) since they carry no
    connectivity-failure signal.
    """

    timestamp: str
    kind: str                 # "disconnection" | "association"
    ssid: Optional[str]
    bssid: Optional[str]
    reason_code: Optional[int]        # 802.11 reason code, disconnection only
    reason_name: Optional[str]
    locally_generated: Optional[bool]  # disconnection only
    roam: Optional[bool]               # association only
    source_ref: SourceRef


@dataclass
class BatteryUidStats:
    """One `UID <token>: <mAh> [fg: ...] [bg: ...] [fgs: ...] [cached: ...]`
    entry from `DUMP OF SERVICE batterystats` -> "Estimated power use
    (mAh):" -- per-app/per-uid battery attribution, broken down by
    foreground/background/foreground-service/cached state and by
    component (cpu, screen, audio, wifi, mobile_radio, wakelock, camera,
    video, sensors, gnss).

    `uid` is the real numeric UID (parsed from either a raw integer token
    like "1000", or a "u<userId>a<appId>" token, converted via
    uid = userId*100000 + appId -- verified against real data). `package`
    is filled in downstream by matching `uid % 100000` against a known
    package's `appId` (see app/services/ingestion.py); it stays None for
    system UIDs that aren't any installed app's appId.
    """

    uid_token: str
    uid: int
    package: Optional[str]
    total_mah: float
    fg_mah: Optional[float]
    bg_mah: Optional[float]
    fgs_mah: Optional[float]
    cached_mah: Optional[float]
    components_mah: dict          # {"cpu": 7.05, "audio": 28.8, "wifi": 0.033, ...}
    source_ref: SourceRef


@dataclass
class CdmPairingEvent:
    """One Companion Device Manager / Fast Pair event from the system log --
    the actual device-pairing flow (Bluetooth discovery, association,
    secure-channel handshake) for Wear OS / Fast Pair companion pairing.
    Verified against a real pairing session (a Pixel phone pairing with a
    Pixel Watch): CDM_CompanionDeviceDiscoveryService, CDM_Association*,
    CDM_BluetoothDeviceProcessor, CDM_DevicePresenceProcessor,
    CDM_SecureChannel, CDM_CompanionTransport* tags, plus
    com.google.android.gms's Fast Pair UI (HalfSheetActivity).

    Well-known milestones get a specific `kind`; anything else at W/E log
    level from a CDM_* tag (or FastPair-related activity) is still
    captured as kind="anomaly" with the raw line in `detail` -- real
    failure message text can't be fully enumerated in advance, but the log
    level itself reliably flags something worth surfacing.
    """

    timestamp: str
    level: str                      # D | I | W | E | V, as printed
    tag: str                        # e.g. "CDM_AssociationStore"
    kind: str                       # "device_found" | "association_requested" |
                                      # "association_approved" | "association_added" |
                                      # "association_updated" | "bt_device_connected" |
                                      # "device_presence_connected" | "fast_pair_ui_opened" |
                                      # "secure_channel_established" | "anomaly"
    mac_address: Optional[str]
    display_name: Optional[str]
    package_name: Optional[str]     # owning app, e.g. com.google.android.apps.wear.companion
    association_id: Optional[int]
    detail: str                     # raw trailing message text
    source_ref: SourceRef


@dataclass
class LocationProviderState:
    """One location provider's last known fix.

    `latitude`/`longitude` are a real physical position -- often someone's
    home. They are kept locally for the UI; use location.redacted_coords()
    before putting a fix into anything sent off-device.
    """

    name: str                        # "gps" | "network" | "fused" | "passive" | ...
    last_fix_provider: Optional[str]  # provider named INSIDE the fix, may differ
    latitude: Optional[float]
    longitude: Optional[float]
    horizontal_accuracy_m: Optional[float]
    satellites: Optional[int]        # GPS fixes only; others carry no satellite bundle
    max_cn0: Optional[float]
    mean_cn0: Optional[float]
    source_ref: SourceRef


@dataclass
class LocationAppUsage:
    """How much location one app drew from one provider, since boot.

    `locations` is the count actually DELIVERED, which is the interesting
    number: an app requesting 1 Hz that received far fewer was not being
    served at the rate it asked for.
    """

    provider: str
    uid: int
    package: str
    tag: Optional[str]
    min_interval: str                # kept as printed ("0s", "passive", ...)
    max_interval: str
    total_duration: str
    foreground_duration: str
    locations: int
    source_ref: SourceRef


@dataclass
class GnssKpi:
    """Since-boot GNSS aggregates from the KPI block.

    These cover the whole uptime and CANNOT be attributed to any single
    time window -- a caller reporting them must say so, or it implies a
    precision the numbers do not have.
    """

    location_failure_pct: Optional[float]
    location_reports: Optional[int]
    ttff_reports: Optional[int]
    ttff_mean_sec: Optional[float]
    ttff_stddev_sec: Optional[float]
    accuracy_reports: Optional[int]
    accuracy_mean_m: Optional[float]
    accuracy_stddev_m: Optional[float]
    cn0_mean_dbhz: Optional[float]
    cn0_stddev_dbhz: Optional[float]
    cn0_threshold_dbhz: Optional[float]      # the good/poor boundary this build used
    cn0_time_above_threshold_min: Optional[float]
    cn0_time_below_threshold_min: Optional[float]
    constellations: Optional[str]


@dataclass
class LocationSnapshot:
    location_enabled: Optional[bool]
    gnss_hardware_model: Optional[str]
    providers: list["LocationProviderState"]
    app_usage: list["LocationAppUsage"]
    kpi: Optional["GnssKpi"]
    source_ref: SourceRef


@dataclass
class GnssSignalInterval:
    """A span during which GPS reception held one quality classification.

    `quality` is Android's own label. "good"/"poor" are thresholded on the
    top-4-average carrier-to-noise ratio; "none" means no fix -- either
    still acquiring or GPS off -- and is NOT a reading of bad reception.

    Reception quality is not position error. A poor interval means weak
    satellite signal; it does not establish that any app received a wrong
    position, which these logs never record.
    """

    quality: str                     # "good" | "poor" | "none"
    start_timestamp: str
    end_timestamp: str
    duration_sec: int
    active_uids: Optional[str]       # comma-joined uids holding GPS during the span
    gps_active: bool
    source_ref: SourceRef


@dataclass
class ProcessMemoryUsage:
    """One row of a `dumpsys meminfo` per-process ranking table. Which
    metric `memory_kb` holds depends on which table it came from (RSS or
    PSS) -- the caller keeps them in separate lists rather than mixing
    two different measurements into one number."""

    process: str
    pid: int
    memory_kb: int
    swap_kb: Optional[int]
    state: Optional[str]        # e.g. "activities" from "(pid 6609 / activities)"
    source_ref: SourceRef


@dataclass
class MemorySnapshot:
    """System-wide memory state at capture time, from `dumpsys meminfo`.

    Every field is Optional because the exact lines printed vary by
    Android version and build -- an absent field is reported as unknown
    rather than zero.
    """

    total_ram_kb: Optional[int]
    free_ram_kb: Optional[int]
    used_ram_kb: Optional[int]
    lost_ram_kb: Optional[int]
    cached_pss_kb: Optional[int]
    cached_kernel_kb: Optional[int]
    truly_free_kb: Optional[int]      # the "N K free" term inside Free RAM
    used_pss_kb: Optional[int]
    kernel_kb: Optional[int]
    zram_physical_kb: Optional[int]
    zram_in_swap_kb: Optional[int]
    total_swap_kb: Optional[int]
    status: Optional[str]             # e.g. "normal", "moderate", "low", "critical"
    top_by_rss: list["ProcessMemoryUsage"]
    top_by_pss: list["ProcessMemoryUsage"]
    source_ref: SourceRef


@dataclass
class ProcessMemorySample:
    """One `am_pss` sample -- a per-process memory reading at a moment in
    time. Repeated samples of the same pid are what make memory growth
    visible at all.

    `pss_kb` is None when the build didn't collect PSS (common on modern
    Android, where only RSS is populated) -- None means not measured, NOT
    measured-as-zero.
    """

    timestamp: str
    pid: Optional[int]
    uid: Optional[int]
    process: str
    package: Optional[str]
    pss_kb: Optional[int]
    rss_kb: Optional[int]
    swap_pss_kb: Optional[int]
    proc_state: Optional[int]
    source_ref: SourceRef


@dataclass
class ProcessKillEvent:
    """An ActivityManager process kill (am_kill) or death (am_proc_died).

    `kind` distinguishes them: a "kill" carries a `reason` explaining why
    the system killed it; a "died" only records that the process went away
    and does NOT by itself establish the system killed it deliberately.
    `oom_adj` is the raw killability score (roughly 0 = foreground/critical,
    up toward ~1000 = empty cached), reported without interpretation since
    the exact bands vary by Android version and device policy.
    """

    timestamp: str
    kind: str                       # "kill" | "died"
    user_id: Optional[int]
    pid: Optional[int]
    process: str                    # may be "pkg:subprocess"
    package: Optional[str]          # the part before ":", when present
    oom_adj: Optional[int]
    reason: Optional[str]           # am_kill only
    rss_kb: Optional[int]           # am_kill on newer builds only
    proc_state: Optional[int]       # am_proc_died only
    source_ref: SourceRef


@dataclass
class SelinuxDenial:
    """One SELinux AVC denial from the system log.

    `enforcing` is the field that decides whether this is a real failure:
    True (permissive=0) means the operation was actually blocked; False
    (permissive=1) means it was logged but allowed through anyway. None
    means the log line didn't say -- reported as unknown, not assumed.
    """

    timestamp: str
    verdict: str                        # "denied" | "granted"
    permissions: list[str]              # e.g. ["read"], ["read", "write"]
    source_context: Optional[str]       # full u:r:domain:s0:c... string
    source_domain: Optional[str]        # just the type component, e.g. "platform_app"
    target_context: Optional[str]
    target_type: Optional[str]          # e.g. "sysfs"
    target_class: Optional[str]         # e.g. "file", "dir", "unix_stream_socket"
    comm: Optional[str]                 # the thread/process name, when logged
    target_name: Optional[str]          # the object name, when logged
    app: Optional[str]                  # package, when the line carries app=
    enforcing: Optional[bool]
    source_ref: SourceRef


@dataclass
class CompanionDeviceAssociation:
    """One entry from `DUMP OF SERVICE companiondevice`'s "Companion Device
    Associations:" list -- the CDM service's OWN current-state record of a
    paired companion device at the moment the bugreport was taken, not
    reconstructed from log-line events (contrast with CdmPairingEvent).
    `currently_connected` is cross-referenced from the same section's
    "Connected Bluetooth Devices:" list by matching mac_address.
    """

    association_id: int
    mac_address: Optional[str]
    display_name: Optional[str]
    package_name: Optional[str]
    device_profile: Optional[str]
    self_managed: Optional[bool]
    revoked: Optional[bool]
    pending: Optional[bool]
    trusted: Optional[bool]
    time_approved: Optional[str]        # raw Java Date.toString(), e.g. "Thu Jun 25 10:08:12 PDT 2026"
    last_time_connected: Optional[str]  # raw value, "None" if never connected since approval
    currently_connected: Optional[bool]
    source_ref: SourceRef


@dataclass
class ParsedCapture:
    """Everything a capture's ingestion pipeline produced, ground-truth facts only."""

    focus_stack: list[FocusStackEntry] = field(default_factory=list)
    focus_events: list[FocusEvent] = field(default_factory=list)
    packages: dict[str, PackageFacts] = field(default_factory=dict)
    media_sessions: list[MediaSessionFacts] = field(default_factory=list)
    foreground_services: list[ForegroundServiceFacts] = field(default_factory=list)
    freeze_events: list[ProcessFreezeEvent] = field(default_factory=list)
    crash_events: list[CrashEvent] = field(default_factory=list)
    tombstones: list[TombstoneFacts] = field(default_factory=list)
    anrs: list[AnrFacts] = field(default_factory=list)
    bt_hci_summary: Optional[BtHciSummary] = None
    packet_capture_summary: Optional[PacketCaptureSummary] = None
    packet_analysis: Optional[PacketAnalysis] = None
    wifi_events: list[WifiEvent] = field(default_factory=list)
    battery_uid_stats: list[BatteryUidStats] = field(default_factory=list)
    cdm_pairing_events: list[CdmPairingEvent] = field(default_factory=list)
    companion_device_associations: list[CompanionDeviceAssociation] = field(default_factory=list)
    selinux_denials: list[SelinuxDenial] = field(default_factory=list)
    process_kills: list[ProcessKillEvent] = field(default_factory=list)
    memory_snapshot: Optional[MemorySnapshot] = None
    location_snapshot: Optional[LocationSnapshot] = None
    gnss_signal_intervals: list[GnssSignalInterval] = field(default_factory=list)
    memory_samples: list[ProcessMemorySample] = field(default_factory=list)
    device_info: Optional[DeviceInfo] = None
    parse_warnings: list[str] = field(default_factory=list)
