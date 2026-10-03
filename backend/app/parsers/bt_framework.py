"""Parser for Android framework Bluetooth dumpsys text
(`DUMP OF SERVICE bluetooth_manager`) — adapter enable / adapter state
machine, ACL Connection Events, Bond Events, and profile connection-state
changes from BluetoothActiveDeviceManager.

This is intentionally separate from `bt_hci.py` (binary HCI snoop). Formats
were verified against a real Pixel bugreport's bluetooth_manager dump;
synthetic fixtures in tests use the same shapes with lab-only addresses.

Invent-nothing: disconnect reason codes use the HCI status name table when
known, else `Unknown (0xNN)`. Bond / adapter tokens not in the observed
tables stay Unknown / raw as printed.
"""
from __future__ import annotations

import re

from app.parsers.base import BtFrameworkEvent, SourceRef
from app.parsers.bt_hci import HCI_STATUS_NAMES
from app.parsers.section_extractor import Section

BOND_STATE_NAMES = {
    0x0: "BT_BOND_STATE_NONE",
    0x1: "BT_BOND_STATE_BONDING",
    0x2: "BT_BOND_STATE_BONDED",
}

ADAPTER_EVENT_NAMES = {
    "BLE_TURN_ON",
    "BLE_STARTED",
    "USER_TURN_ON",
    "BREDR_STARTED",
    "USER_TURN_OFF",
    "BLE_TURN_OFF",
    "BREDR_STOPPED",
    "BLE_STOPPED",
}

CONN_RE = re.compile(
    r"^\s*(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<action>CONNECTED|DISCONNECTED)\s+"
    r"(?P<addr>[0-9a-fA-F:]{17})"
    r"(?:\s+reason=(?P<reason>\d+))?\s*$"
)

BOND_RE = re.compile(
    r"^\s*(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<addr>[0-9a-fA-F:]{17})\s+"
    r"(?P<fn>bond_state_changed|btif_dm_create_bond|btif_dm_remove_bond)\s+"
    r"(?P<state>BT_BOND_STATE_\w+)\((?P<code>0x[0-9a-fA-F]+)\)\s*$"
)

ENABLE_RE = re.compile(
    r"^\s*(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<action>Enable|Disable)\s+"
    r"(?P<reason>\S+)\s+"
    r"(?P<package>\S+)\s*$"
)

ADAPTER_REC_RE = re.compile(
    r"^\s*rec\[\d+\]: time=(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r".*?what=\d+\(0x[0-9a-fA-F]+\)\s+(?P<event>\S+)\s*$"
)

# Real dump glues MAC to from-state with no space: "AA:BB:..:FFSTATE_CONNECTING".
PROFILE_RE = re.compile(
    r"^\s*(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"\[From Service\]\s+(?P<profile>\S+)\s+connection state changed:\s+"
    r"(?P<addr>[0-9a-fA-F:]{17})"
    r"(?P<from>STATE_\w+)\s*->\s*(?P<to>STATE_\w+)\s*$"
)

SECTION = "bluetooth_manager"

# Headers that open a parse mode. Any other non-indented "Foo:" header clears mode.
MODE_HEADERS = {
    "Connection Events:": "connection",
    "Bond Events:": "bond",
    "Enable log:": "enable",
    "Bluetooth Activity History:": "enable",
    "BluetoothAdapterState:": "adapter_sm",
    "BluetoothActiveDeviceManager event log:": "profile",
}


def _reason_name(code: int) -> str:
    return HCI_STATUS_NAMES.get(code, f"Unknown (0x{code:02X})")


def _bond_state_name(code: int, printed: str) -> str:
    return BOND_STATE_NAMES.get(code, f"Unknown ({printed})")


def parse_bt_framework_events(section: Section) -> list[BtFrameworkEvent]:
    out: list[BtFrameworkEvent] = []
    mode: str | None = None

    for i, raw in enumerate(section.lines):
        abs_line = section.line_start + i
        ref = SourceRef(SECTION, abs_line, abs_line)
        stripped = raw.strip()

        if stripped in MODE_HEADERS:
            mode = MODE_HEADERS[stripped]
            continue
        # Clear mode on a new top-level dumpsys header (non-indented Name:).
        if (
            mode is not None
            and raw.startswith(("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
                                "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
                                "W", "X", "Y", "Z"))
            and stripped.endswith(":")
            and not stripped.startswith("rec[")
            and stripped not in MODE_HEADERS
        ):
            mode = None
            # fall through — this header line itself is not an event

        if mode == "connection":
            m = CONN_RE.match(raw)
            if not m:
                continue
            reason_code = int(m.group("reason")) if m.group("reason") else None
            out.append(BtFrameworkEvent(
                timestamp=m.group("ts"), kind="connection", action=m.group("action"),
                profile=None, address=m.group("addr").lower(),
                from_state=None, to_state=None,
                reason_code=reason_code,
                reason_name=_reason_name(reason_code) if reason_code is not None else None,
                detail=stripped, source_ref=ref,
            ))
        elif mode == "bond":
            if stripped.startswith("Total Number") or stripped.startswith("Time "):
                continue
            m = BOND_RE.match(raw)
            if not m:
                continue
            code = int(m.group("code"), 16)
            state_name = _bond_state_name(code, m.group("state"))
            out.append(BtFrameworkEvent(
                timestamp=m.group("ts"), kind="bond", action=m.group("fn"),
                profile=None, address=m.group("addr").lower(),
                from_state=None, to_state=state_name,
                reason_code=code, reason_name=state_name,
                detail=stripped, source_ref=ref,
            ))
        elif mode == "enable":
            if stripped.startswith("TIMESTAMP") or set(stripped) <= {"-", " "}:
                continue
            m = ENABLE_RE.match(raw)
            if not m:
                continue
            out.append(BtFrameworkEvent(
                timestamp=m.group("ts"), kind="adapter_enable", action=m.group("action"),
                profile=None, address=None, from_state=None, to_state=None,
                reason_code=None, reason_name=m.group("reason"),
                detail=f"{m.group('reason')} {m.group('package')}", source_ref=ref,
            ))
        elif mode == "adapter_sm":
            m = ADAPTER_REC_RE.match(raw)
            if not m:
                continue
            event = m.group("event")
            name = event if event in ADAPTER_EVENT_NAMES else f"Unknown ({event})"
            out.append(BtFrameworkEvent(
                timestamp=m.group("ts"), kind="adapter_state", action=name,
                profile=None, address=None, from_state=None, to_state=None,
                reason_code=None, reason_name=None, detail=stripped, source_ref=ref,
            ))
        elif mode == "profile":
            m = PROFILE_RE.match(raw)
            if not m:
                continue
            out.append(BtFrameworkEvent(
                timestamp=m.group("ts"), kind="profile_connection",
                action=f"{m.group('from')}->{m.group('to')}",
                profile=m.group("profile"), address=m.group("addr").lower(),
                from_state=m.group("from"), to_state=m.group("to"),
                reason_code=None, reason_name=None, detail=stripped, source_ref=ref,
            ))

    return out
