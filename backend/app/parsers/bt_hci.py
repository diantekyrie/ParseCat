"""Parser for the on-device Bluetooth HCI snoop log (a file somewhere under
FS/data/misc/bluetooth/logs/ inside the bugreport zip -- a separate binary
file, not text inside the flattened bugreport txt). The exact filename
varies by OEM/build -- seen in the wild as "btsnooz_hci.log",
"btsnoop_hci.log.filtered", and rotated ".last" copies of either -- see
BT_HCI_LOG_CANDIDATES in ingestion.py, which searches for all of them.

Despite some of those names ("btsnooz", with an extra z -- Android's name
for a compressed, bugreport-inline HCI log variant documented in AOSP's
btsnooz.py), every real file seen so far has verified directly against the
classic `btsnoop` binary format (RFC-adjacent, used by Wireshark and the
original Symbian/Nokia btsnoop tool), not the compressed variant:

    header (16 bytes):  b"btsnoop\\x00" + version(u32 BE) + datalink_type(u32 BE)
    record (24-byte header + payload), repeated:
        original_length(u32 BE), included_length(u32 BE), flags(u32 BE),
        cumulative_drops(u32 BE), timestamp(u64 BE, see below)
        payload: included_length bytes

Android's on-device logger uses datalink_type 1002, which (verified against
real captured bytes here -- distribution of H4 type bytes and decoded event
codes/statuses all came out as valid, sane HCI semantics) means each
payload's first byte is a standard "H4" packet-type indicator: 0x01=Command,
0x02=ACL data, 0x03=SCO data, 0x04=Event, 0x05=ISO data.

Timestamp: microseconds since 0000-01-01 (proleptic Gregorian), per the
original btsnoop spec. BTSNOOP_EPOCH_DELTA_USEC converts to Unix epoch;
verified against this exact file by confirming decoded timestamps land
within minutes of the bugreport's own capture time.

Invent-nothing: HCI status / encryption-enabled / link-key-type codes not
in the tables below stay "Unknown (...)". Link-key bytes and BD_ADDR from
pairing events are never stored on decoded facts (secret / PII).
"""
from __future__ import annotations

import datetime
import struct
from collections import defaultdict

from app.parsers.base import (
    BtHciEvent,
    BtHciHandleFailureSequence,
    BtHciSummary,
    SourceRef,
)

MAGIC = b"btsnoop\x00"
HEADER_LEN = 16
RECORD_HEADER_LEN = 24

BTSNOOP_EPOCH_DELTA_USEC = 0x00DCDDB30F2F8000

H4_COMMAND, H4_ACL, H4_SCO, H4_EVENT, H4_ISO = 0x01, 0x02, 0x03, 0x04, 0x05

# HCI event codes (Bluetooth Core Spec Vol 2 Part E) -- only the subset we
# decode per-record. Event codes and HCI status/error codes are different
# namespaces that happen to overlap numerically in places.
EVT_CONNECTION_COMPLETE = 0x03
EVT_DISCONNECTION_COMPLETE = 0x05
EVT_AUTHENTICATION_COMPLETE = 0x06
EVT_ENCRYPTION_CHANGE = 0x08
EVT_CHANGE_CONNECTION_LINK_KEY_COMPLETE = 0x09
EVT_COMMAND_COMPLETE = 0x0E
EVT_COMMAND_STATUS = 0x0F
EVT_LINK_KEY_REQUEST = 0x17
EVT_LINK_KEY_NOTIFICATION = 0x18
EVT_SIMPLE_PAIRING_COMPLETE = 0x36
EVT_LE_META = 0x3E
LE_SUBEVT_CONNECTION_COMPLETE = 0x01
LE_SUBEVT_ENHANCED_CONNECTION_COMPLETE = 0x0A

# Bluetooth Core Spec HCI Error Codes -- the subset most relevant to
# diagnosing pairing/connection/coexistence failures. Anything not listed
# here is reported as "Unknown (0xNN)" rather than guessed.
HCI_STATUS_NAMES = {
    0x00: "Success",
    0x01: "Unknown HCI Command",
    0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure",
    0x04: "Page Timeout",
    0x05: "Authentication Failure",
    0x06: "PIN or Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x09: "Connection Limit Exceeded",
    0x0C: "Command Disallowed",
    0x0D: "Connection Rejected due to Limited Resources",
    0x0E: "Connection Rejected due to Security Reasons",
    0x0F: "Connection Rejected due to Unacceptable BD_ADDR",
    0x10: "Connection Accept Timeout Exceeded",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection due to Low Resources",
    0x15: "Remote Device Terminated Connection due to Power Off",
    0x16: "Connection Terminated by Local Host",
    0x17: "Repeated Attempts",
    0x18: "Pairing Not Allowed",
    0x19: "Unknown LMP PDU",
    0x1A: "Unsupported Remote Feature",
    0x1B: "SCO Offset Rejected",
    0x1C: "SCO Interval Rejected",
    0x1D: "SCO Air Mode Rejected",
    0x1E: "Invalid LMP/LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LMP/LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x22: "LMP/LL Response Timeout",
    0x23: "LMP Error Transaction Collision / LL Procedure Collision",
    0x24: "LMP PDU Not Allowed",
    0x25: "Encryption Mode Not Acceptable",
    0x28: "Instant Passed",
    0x29: "Pairing with Unit Key Not Supported",
    0x2A: "Different Transaction Collision",
    0x3A: "Controller Busy",
    0x3B: "Unacceptable Connection Parameters",
    0x3D: "Connection Failed to be Established (Synchronization Timeout)",
    0x3E: "Connection Failed to be Established",
}

# Encryption_Enabled values from HCI Encryption Change event (Core Spec).
# Values outside this table stay Unknown -- never invent.
ENCRYPTION_ENABLED_NAMES = {
    0x00: "Link-level encryption OFF",
    0x01: "Link-level encryption ON (E0 for BR/EDR or AES-CCM for LE)",
    0x02: "Link-level encryption ON (AES-CCM for BR/EDR)",
}

# Link_Key_Type values from HCI Link Key Notification event (Core Spec).
# Values outside this table stay Unknown -- never invent. The 16-byte link
# key itself is never stored.
LINK_KEY_TYPE_NAMES = {
    0x00: "Combination key",
    0x01: "Local Unit key",
    0x02: "Remote Unit key",
    0x03: "Debug Combination key",
    0x04: "Unauthenticated Combination key from P-192",
    0x05: "Authenticated Combination key from P-192",
    0x06: "Changed Combination key",
    0x07: "Unauthenticated Combination key from P-256",
    0x08: "Authenticated Combination key from P-256",
}

# Kinds that count as security/pairing path failures when status != Success.
_SECURITY_FAILURE_KINDS = frozenset({
    "authentication_complete",
    "encryption_change",
    "simple_pairing_complete",
    "change_connection_link_key_complete",
})


def _status_name(code: int) -> str:
    return HCI_STATUS_NAMES.get(code, f"Unknown (0x{code:02X})")


def _encryption_enabled_name(code: int) -> str:
    return ENCRYPTION_ENABLED_NAMES.get(code, f"Unknown (0x{code:02X})")


def _link_key_type_name(code: int) -> str:
    return LINK_KEY_TYPE_NAMES.get(code, f"Unknown (0x{code:02X})")


def _to_iso(ts_field: int) -> str:
    unix_usec = ts_field - BTSNOOP_EPOCH_DELTA_USEC
    return datetime.datetime.utcfromtimestamp(unix_usec / 1_000_000).isoformat(timespec="milliseconds") + "Z"


def _source_ref(record_index: int) -> SourceRef:
    # Binary btsnoop has no text lines; cite 1-indexed record index.
    return SourceRef("bt_hci", record_index, record_index)


def _severity_confidence(
    kind: str,
    status_code: int | None,
    reason_code: int | None = None,
    *,
    status_name: str | None = None,
) -> tuple[str, str]:
    """Code-owned severity/confidence for one decoded HCI fact.

    HIGH whenever the event structure decoded cleanly. Unknown status/reason
    *names* stay Unknown (invent-nothing) but confidence remains HIGH that
    the numeric code was read from the record. MEDIUM only if we lack a
    status for a kind that normally carries one (should not happen for
    current decoders).
    """
    if status_code is None and kind not in (
        "link_key_request",
        "link_key_notification",
    ):
        return "warning", "MEDIUM"

    failed_status = status_code is not None and status_code != 0
    failed_reason = reason_code is not None and reason_code != 0

    if kind == "disconnection_complete" and failed_reason:
        # Auth-ish disconnect reasons get critical; others warning.
        if reason_code in (0x05, 0x06, 0x0E, 0x18, 0x25):
            return "critical", "HIGH"
        return "warning", "HIGH"

    if failed_status:
        if kind in _SECURITY_FAILURE_KINDS or status_code in (0x05, 0x06, 0x18, 0x25):
            return "critical", "HIGH"
        return "warning", "HIGH"

    # Successful auth/encrypt/pairing or neutral lifecycle events.
    if kind in _SECURITY_FAILURE_KINDS or kind in (
        "link_key_request",
        "link_key_notification",
    ):
        return "info", "HIGH"

    if status_name and status_name.startswith("Unknown"):
        return "warning", "HIGH"

    return "info", "HIGH"


def _make_event(
    *,
    timestamp: str,
    kind: str,
    record_index: int,
    status_code: int | None = None,
    handle: int | None = None,
    reason_code: int | None = None,
    opcode: int | None = None,
    encryption_enabled: int | None = None,
    key_type: int | None = None,
    reason_name_override: str | None = None,
) -> BtHciEvent:
    status_name = _status_name(status_code) if status_code is not None else None
    if reason_name_override is not None:
        reason_name = reason_name_override
    elif reason_code is not None:
        reason_name = _status_name(reason_code)
    else:
        reason_name = None
    severity, confidence = _severity_confidence(
        kind, status_code, reason_code, status_name=status_name,
    )
    return BtHciEvent(
        timestamp=timestamp,
        kind=kind,
        status_code=status_code,
        status_name=status_name,
        handle=handle,
        reason_code=reason_code,
        reason_name=reason_name,
        opcode=opcode,
        encryption_enabled=encryption_enabled,
        key_type=key_type,
        source_ref=_source_ref(record_index),
        severity=severity,
        confidence=confidence,
    )


def build_handle_failure_sequences(
    events: list[BtHciEvent],
) -> list[BtHciHandleFailureSequence]:
    """Group decoded events by connection handle and keep sequences that
    include a non-success status (or security-path failure) and end with
    disconnection_complete. Handles without a disconnect trailer are omitted.
    """
    by_handle: dict[int, list[BtHciEvent]] = defaultdict(list)
    for e in events:
        if e.handle is None:
            continue
        by_handle[e.handle].append(e)

    out: list[BtHciHandleFailureSequence] = []
    for handle, hevents in by_handle.items():
        if not hevents or hevents[-1].kind != "disconnection_complete":
            continue
        had_failure = any(
            (e.status_code is not None and e.status_code != 0)
            or (e.kind == "disconnection_complete" and (e.reason_code or 0) != 0)
            or (e.kind in _SECURITY_FAILURE_KINDS and (e.status_code or 0) != 0)
            for e in hevents
        )
        # Also accept "auth fail then disconnect" where disconnect reason is
        # the only failure signal (status on disconnect event is often 0).
        if not had_failure:
            continue
        disc = hevents[-1]
        out.append(BtHciHandleFailureSequence(
            handle=handle,
            disconnect_reason_code=disc.reason_code,
            disconnect_reason_name=disc.reason_name,
            events=list(hevents),
        ))
    return out


def parse_bt_hci_log(data: bytes) -> BtHciSummary | None:
    if len(data) < HEADER_LEN or data[:8] != MAGIC:
        return None

    _version, _datalink = struct.unpack(">II", data[8:16])

    off = HEADER_LEN
    total = command_count = event_count = acl_count = 0
    first_ts = last_ts = None
    event_code_counts: dict[str, int] = {}
    decoded_events: list[BtHciEvent] = []
    record_index = 0

    while off + RECORD_HEADER_LEN <= len(data):
        orig_len, incl_len, flags, drops, ts_field = struct.unpack(
            ">IIIIQ", data[off:off + RECORD_HEADER_LEN]
        )
        off += RECORD_HEADER_LEN
        pkt = data[off:off + incl_len]
        off += incl_len
        if incl_len <= 0 or off > len(data):
            break

        total += 1
        record_index += 1
        iso_ts = _to_iso(ts_field)
        if first_ts is None:
            first_ts = iso_ts
        last_ts = iso_ts

        if not pkt:
            continue
        h4_type = pkt[0]

        if h4_type == H4_COMMAND:
            command_count += 1
        elif h4_type == H4_ACL:
            acl_count += 1
        elif h4_type == H4_EVENT and len(pkt) >= 3:
            event_count += 1
            event_code = pkt[1]
            event_code_counts[f"0x{event_code:02X}"] = event_code_counts.get(f"0x{event_code:02X}", 0) + 1
            params = pkt[3:]

            if event_code == EVT_DISCONNECTION_COMPLETE and len(params) >= 4:
                status, handle, reason = params[0], struct.unpack("<H", params[1:3])[0], params[3]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="disconnection_complete",
                    record_index=record_index,
                    status_code=status, handle=handle, reason_code=reason,
                ))
            elif event_code == EVT_CONNECTION_COMPLETE and len(params) >= 3:
                status, handle = params[0], struct.unpack("<H", params[1:3])[0]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="connection_complete",
                    record_index=record_index,
                    status_code=status, handle=handle,
                ))
            elif event_code == EVT_AUTHENTICATION_COMPLETE and len(params) >= 3:
                status, handle = params[0], struct.unpack("<H", params[1:3])[0]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="authentication_complete",
                    record_index=record_index,
                    status_code=status, handle=handle,
                ))
            elif event_code == EVT_ENCRYPTION_CHANGE and len(params) >= 4:
                status, handle, enc = params[0], struct.unpack("<H", params[1:3])[0], params[3]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="encryption_change",
                    record_index=record_index,
                    status_code=status, handle=handle,
                    encryption_enabled=enc,
                    reason_code=enc,
                    reason_name_override=_encryption_enabled_name(enc),
                ))
            elif event_code == EVT_CHANGE_CONNECTION_LINK_KEY_COMPLETE and len(params) >= 3:
                status, handle = params[0], struct.unpack("<H", params[1:3])[0]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="change_connection_link_key_complete",
                    record_index=record_index,
                    status_code=status, handle=handle,
                ))
            elif event_code == EVT_LINK_KEY_REQUEST and len(params) >= 6:
                # BD_ADDR is present but deliberately not stored (PII).
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="link_key_request",
                    record_index=record_index,
                ))
            elif event_code == EVT_LINK_KEY_NOTIFICATION and len(params) >= 23:
                # params: BD_ADDR(6) + Link_Key(16) + Key_Type(1). Store only
                # Key_Type; never the address or key bytes.
                key_type = params[22]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="link_key_notification",
                    record_index=record_index,
                    key_type=key_type,
                    reason_code=key_type,
                    reason_name_override=_link_key_type_name(key_type),
                ))
            elif event_code == EVT_SIMPLE_PAIRING_COMPLETE and len(params) >= 1:
                # Status + BD_ADDR(6); address deliberately not stored.
                status = params[0]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="simple_pairing_complete",
                    record_index=record_index,
                    status_code=status,
                ))
            elif event_code == EVT_COMMAND_COMPLETE and len(params) >= 4:
                opcode, status = struct.unpack("<H", params[1:3])[0], params[3]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="command_complete",
                    record_index=record_index,
                    status_code=status, opcode=opcode,
                ))
            elif event_code == EVT_COMMAND_STATUS and len(params) >= 4:
                status, opcode = params[0], struct.unpack("<H", params[2:4])[0]
                decoded_events.append(_make_event(
                    timestamp=iso_ts, kind="command_status",
                    record_index=record_index,
                    status_code=status, opcode=opcode,
                ))
            elif event_code == EVT_LE_META and len(params) >= 1:
                subevent = params[0]
                if subevent in (LE_SUBEVT_CONNECTION_COMPLETE, LE_SUBEVT_ENHANCED_CONNECTION_COMPLETE) and len(params) >= 4:
                    status, handle = params[1], struct.unpack("<H", params[2:4])[0]
                    decoded_events.append(_make_event(
                        timestamp=iso_ts, kind="le_connection_complete",
                        record_index=record_index,
                        status_code=status, handle=handle,
                    ))

    if total == 0:
        return None

    return BtHciSummary(
        total_packets=total, command_count=command_count, event_count=event_count,
        acl_data_count=acl_count, first_timestamp=first_ts, last_timestamp=last_ts,
        event_code_counts=event_code_counts, events=decoded_events,
        handle_failure_sequences=build_handle_failure_sequences(decoded_events),
    )
