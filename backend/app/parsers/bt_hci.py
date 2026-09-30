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
"""
from __future__ import annotations

import datetime
import struct

from app.parsers.base import BtHciEvent, BtHciSummary

MAGIC = b"btsnoop\x00"
HEADER_LEN = 16
RECORD_HEADER_LEN = 24

BTSNOOP_EPOCH_DELTA_USEC = 0x00DCDDB30F2F8000

H4_COMMAND, H4_ACL, H4_SCO, H4_EVENT, H4_ISO = 0x01, 0x02, 0x03, 0x04, 0x05

EVT_DISCONNECTION_COMPLETE = 0x05
EVT_CONNECTION_COMPLETE = 0x03
EVT_COMMAND_COMPLETE = 0x0E
EVT_COMMAND_STATUS = 0x0F
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


def _status_name(code: int) -> str:
    return HCI_STATUS_NAMES.get(code, f"Unknown (0x{code:02X})")


def _to_iso(ts_field: int) -> str:
    unix_usec = ts_field - BTSNOOP_EPOCH_DELTA_USEC
    return datetime.datetime.utcfromtimestamp(unix_usec / 1_000_000).isoformat(timespec="milliseconds") + "Z"


def parse_bt_hci_log(data: bytes) -> BtHciSummary | None:
    if len(data) < HEADER_LEN or data[:8] != MAGIC:
        return None

    _version, _datalink = struct.unpack(">II", data[8:16])

    off = HEADER_LEN
    total = command_count = event_count = acl_count = 0
    first_ts = last_ts = None
    event_code_counts: dict[str, int] = {}
    decoded_events: list[BtHciEvent] = []

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
                decoded_events.append(BtHciEvent(
                    timestamp=iso_ts, kind="disconnection_complete",
                    status_code=status, status_name=_status_name(status),
                    handle=handle, reason_code=reason, reason_name=_status_name(reason),
                    opcode=None,
                ))
            elif event_code == EVT_CONNECTION_COMPLETE and len(params) >= 3:
                status, handle = params[0], struct.unpack("<H", params[1:3])[0]
                decoded_events.append(BtHciEvent(
                    timestamp=iso_ts, kind="connection_complete",
                    status_code=status, status_name=_status_name(status),
                    handle=handle, reason_code=None, reason_name=None, opcode=None,
                ))
            elif event_code == EVT_COMMAND_COMPLETE and len(params) >= 4:
                opcode, status = struct.unpack("<H", params[1:3])[0], params[3]
                decoded_events.append(BtHciEvent(
                    timestamp=iso_ts, kind="command_complete",
                    status_code=status, status_name=_status_name(status),
                    handle=None, reason_code=None, reason_name=None, opcode=opcode,
                ))
            elif event_code == EVT_COMMAND_STATUS and len(params) >= 4:
                status, opcode = params[0], struct.unpack("<H", params[2:4])[0]
                decoded_events.append(BtHciEvent(
                    timestamp=iso_ts, kind="command_status",
                    status_code=status, status_name=_status_name(status),
                    handle=None, reason_code=None, reason_name=None, opcode=opcode,
                ))
            elif event_code == EVT_LE_META and len(params) >= 1:
                subevent = params[0]
                if subevent in (LE_SUBEVT_CONNECTION_COMPLETE, LE_SUBEVT_ENHANCED_CONNECTION_COMPLETE) and len(params) >= 4:
                    status, handle = params[1], struct.unpack("<H", params[2:4])[0]
                    decoded_events.append(BtHciEvent(
                        timestamp=iso_ts, kind="le_connection_complete",
                        status_code=status, status_name=_status_name(status),
                        handle=handle, reason_code=None, reason_name=None, opcode=None,
                    ))

    if total == 0:
        return None

    return BtHciSummary(
        total_packets=total, command_count=command_count, event_count=event_count,
        acl_data_count=acl_count, first_timestamp=first_ts, last_timestamp=last_ts,
        event_code_counts=event_code_counts, events=decoded_events,
    )
