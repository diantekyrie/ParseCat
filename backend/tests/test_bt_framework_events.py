"""Round 2 Msg6: framework BT dumpsys parser (adapter / bond / profile).

Synthetic fixtures only — lab MACs, no real captures/PII. Refs #74.
"""
from __future__ import annotations

from app.parsers.bt_framework import parse_bt_framework_events, _reason_name, _bond_state_name
from app.parsers.section_extractor import Section

LAB_ADDR = "aa:bb:cc:dd:ee:01"
LAB_ADDR2 = "aa:bb:cc:dd:ee:02"


def _section(text: str, *, line_start: int = 1) -> Section:
    lines = text.splitlines()
    return Section(
        name="bluetooth_manager",
        priority=None,
        line_start=line_start,
        line_end=line_start + len(lines) - 1,
        lines=lines,
        kind="dumpsys",
    )


FIXTURE = f"""
DUMP OF SERVICE bluetooth_manager:
Enable log:
  TIMESTAMP          ACTION     REASON               PACKAGE
  ------------------ ---------- -------------------- -------
  01-15 10:00:00.000 Enable     SYSTEM_BOOT          android

Bluetooth crashed 0 times

Connection Events:
  01-15 12:00:00.100 CONNECTED    {LAB_ADDR}
  01-15 12:05:00.200 DISCONNECTED {LAB_ADDR} reason=19
  01-15 12:06:00.300 DISCONNECTED {LAB_ADDR2} reason=22
  01-15 12:07:00.400 DISCONNECTED {LAB_ADDR2} reason=254

Bond Events:
  Total Number of events: 4
  Time          address            Function             State
  11:10:21.998  {LAB_ADDR}  bond_state_changed   BT_BOND_STATE_BONDING(0x1)
  11:10:22.073  {LAB_ADDR}  bond_state_changed   BT_BOND_STATE_NONE(0x0)
  16:07:10.176  {LAB_ADDR2}  bond_state_changed   BT_BOND_STATE_BONDED(0x2)
  16:07:07.086  {LAB_ADDR2}  btif_dm_create_bond  BT_BOND_STATE_NONE(0x0)

Link Key Types:

BluetoothActiveDeviceManager event log:
  01-15 13:00:00.100 [From Service] HEADSET connection state changed: {LAB_ADDR.upper()}STATE_CONNECTING -> STATE_CONNECTED
  01-15 13:01:00.200 [From Service] HEADSET connection state changed: {LAB_ADDR.upper()}STATE_CONNECTING -> STATE_DISCONNECTED
  01-15 13:02:00.300 [From Service] LE_AUDIO connection state changed: {LAB_ADDR2.upper()}STATE_CONNECTED -> STATE_DISCONNECTED

BluetoothAdapterState:
 total records=4
  rec[0]: time=01-15 10:00:00.100 processed=Off org=Off dest=TurningBleOn what=3(0x3) BLE_TURN_ON
  rec[1]: time=01-15 10:00:00.150 processed=TurningBleOn org=TurningBleOn dest=BleOn what=7(0x7) BLE_STARTED
  rec[2]: time=01-15 10:00:00.160 processed=BleOn org=BleOn dest=TurningOn what=1(0x1) USER_TURN_ON
  rec[3]: time=01-15 10:00:00.300 processed=TurningOn org=TurningOn dest=On what=5(0x5) BREDR_STARTED
  rec[4]: time=01-15 10:00:01.000 processed=On org=On dest=Off what=9(0x9) MADE_UP_EVENT
 curState=On
""".lstrip()


def test_reason_name_known_and_unknown():
    assert _reason_name(0x13) == "Remote User Terminated Connection"
    assert _reason_name(0x16) == "Connection Terminated by Local Host"
    assert _reason_name(0xFE) == "Unknown (0xFE)"


def test_bond_state_known_and_unknown():
    assert _bond_state_name(0x0, "BT_BOND_STATE_NONE") == "BT_BOND_STATE_NONE"
    assert _bond_state_name(0x99, "BT_BOND_STATE_WEIRD") == "Unknown (BT_BOND_STATE_WEIRD)"


def test_parse_connection_bond_adapter_profile():
    events = parse_bt_framework_events(_section(FIXTURE, line_start=100))
    kinds = {e.kind for e in events}
    assert kinds >= {"adapter_enable", "connection", "bond", "profile_connection", "adapter_state"}

    disc = [e for e in events if e.kind == "connection" and e.action == "DISCONNECTED"]
    assert any(e.reason_code == 19 and e.reason_name == "Remote User Terminated Connection" for e in disc)
    assert any(e.reason_code == 22 and e.reason_name == "Connection Terminated by Local Host" for e in disc)
    assert any(e.reason_code == 254 and e.reason_name == "Unknown (0xFE)" for e in disc)

    bonds = [e for e in events if e.kind == "bond"]
    assert any(e.to_state == "BT_BOND_STATE_NONE" and e.action == "bond_state_changed" for e in bonds)
    assert any(e.to_state == "BT_BOND_STATE_BONDED" for e in bonds)

    # Bond failure shape: BONDING then NONE (same addr) — both events present
    bonding = [e for e in bonds if e.address == LAB_ADDR and e.to_state == "BT_BOND_STATE_BONDING"]
    none = [e for e in bonds if e.address == LAB_ADDR and e.to_state == "BT_BOND_STATE_NONE"]
    assert bonding and none

    profiles = [e for e in events if e.kind == "profile_connection"]
    assert any(e.profile == "HEADSET" and e.from_state == "STATE_CONNECTING" and e.to_state == "STATE_CONNECTED" for e in profiles)
    # profile connect fail: CONNECTING -> DISCONNECTED
    assert any(
        e.profile == "HEADSET" and e.from_state == "STATE_CONNECTING" and e.to_state == "STATE_DISCONNECTED"
        for e in profiles
    )

    adapter = [e for e in events if e.kind == "adapter_state"]
    assert any(e.action == "BLE_TURN_ON" for e in adapter)
    assert any(e.action == "Unknown (MADE_UP_EVENT)" for e in adapter)

    enable = [e for e in events if e.kind == "adapter_enable"]
    assert len(enable) == 1 and enable[0].action == "Enable" and enable[0].reason_name == "SYSTEM_BOOT"

    # SourceRef points at bluetooth_manager with absolute lines
    assert all(e.source_ref.section == "bluetooth_manager" for e in events)
    assert all(e.source_ref.line_start >= 100 for e in events)


def test_empty_section():
    assert parse_bt_framework_events(_section("Bluetooth crashed 0 times\n")) == []
