"""Round 2 Msg6: Wi-Fi supplicant / auth / DHCP beyond SM disconnect.

Synthetic WifiController rec[] fixtures only — lab SSID/BSSID, no real
captures/PII. Refs #75. Does not invent DHCP-failure rec[] shapes.
"""
from __future__ import annotations

from app.parsers.section_extractor import Section
from app.parsers.wifi import (
    KNOWN_SUPPLICANT_STATES,
    parse_wifi_events,
    _supplicant_state_name,
    _reason_name,
)

LAB_SSID = "lab-ap-01"
LAB_BSSID = "02:00:00:00:00:01"


def _section(text: str, *, line_start: int = 1) -> Section:
    lines = text.splitlines()
    return Section(
        name="wifi", priority=None,
        line_start=line_start, line_end=line_start + len(lines) - 1,
        lines=lines, kind="dumpsys",
    )


FIXTURE = f"""
  rec[1]: time=01-15 10:00:00.100 processed=ConnectingOrConnectedState org=L2ConnectingState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=on 0 0 ssid: "{LAB_SSID}" bssid: {LAB_BSSID} nid: 0 frequencyMhz: 5785 state: ASSOCIATING
  rec[2]: time=01-15 10:00:00.200 processed=ConnectingOrConnectedState org=L2ConnectingState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=on 0 0 ssid: "{LAB_SSID}" bssid: {LAB_BSSID} nid: 0 frequencyMhz: 5785 state: ASSOCIATED
  rec[3]: time=01-15 10:00:00.300 processed=ConnectingOrConnectedState org=L2ConnectingState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=on 0 0 ssid: "{LAB_SSID}" bssid: {LAB_BSSID} nid: 0 frequencyMhz: 5785 state: FOUR_WAY_HANDSHAKE
  rec[4]: time=01-15 10:00:00.400 processed=ConnectingOrConnectedState org=L2ConnectingState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=on 0 0 ssid: "{LAB_SSID}" bssid: {LAB_BSSID} nid: 0 frequencyMhz: 5785 state: COMPLETED
  rec[5]: time=01-15 10:00:00.500 processed=ConnectingOrConnectedState org=L2ConnectingState dest=L3ProvisioningState what=NETWORK_CONNECTION_EVENT screen=on 0 false {LAB_BSSID} nid=0 "{LAB_SSID}"WPA_PSK last="other"WPA_PSK
  rec[6]: time=01-15 10:00:00.600 processed=L2ConnectedState org=L3ProvisioningState dest=<null> what=CMD_PRE_DHCP_ACTION screen=on 37 0 txpkts=1,2,3
  rec[7]: time=01-15 10:00:00.700 processed=L2ConnectedState org=L3ProvisioningState dest=<null> what=CMD_POST_DHCP_ACTION screen=on
  rec[8]: time=01-15 10:00:00.800 processed=L2ConnectedState org=L3ProvisioningState dest=<null> what=CMD_IPV4_PROVISIONING_SUCCESS screen=on DhcpResultsParcelable{{baseConfiguration: IP address 10.0.0.2/24 Gateway 10.0.0.1}}
  rec[9]: time=01-15 10:00:00.900 processed=L2ConnectedState org=L3ProvisioningState dest=L3ConnectedState what=CMD_IP_CONFIGURATION_SUCCESSFUL screen=on 37 0
  rec[10]: time=01-15 10:01:00.000 processed=ConnectableState org=DisconnectedState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=off 0 0 ssid: "{LAB_SSID}" bssid: 00:00:00:00:00:00 nid: 0 frequencyMhz: 0 state: DISCONNECTED
  rec[11]: time=01-15 10:02:00.000 processed=ConnectingOrConnectedState org=L3ConnectedState dest=<null> what=SUPPLICANT_STATE_CHANGE_EVENT screen=off 0 0 ssid: "{LAB_SSID}" bssid: {LAB_BSSID} nid: 0 frequencyMhz: 0 state: MADE_UP_STATE
  rec[12]: time=01-15 10:03:00.000 processed=L3ConnectedState org=L3ConnectedState dest=DisconnectedState what=NETWORK_DISCONNECTION_EVENT screen=off ssid: "{LAB_SSID}" bssid: {LAB_BSSID} reasonCode: 15 locallyGenerated: false
  rec[13]: time=01-15 10:04:00.000 processed=L2ConnectedState org=L3ConnectedState dest=<null> what=ASSOCIATED_BSSID_EVENT screen=off 0 0 BSSID={LAB_BSSID} Target Bssid=any Last Bssid={LAB_BSSID} roam=true
  rec[14]: time=01-15 10:05:00.000 processed=L2ConnectedState org=L3ConnectedState dest=<null> what=CMD_UPDATE_AP_CAPABILITY screen=off
""".lstrip()


def test_supplicant_state_known_and_unknown():
    assert _supplicant_state_name("FOUR_WAY_HANDSHAKE") == "FOUR_WAY_HANDSHAKE"
    assert "FOUR_WAY_HANDSHAKE" in KNOWN_SUPPLICANT_STATES
    assert _supplicant_state_name("MADE_UP_STATE") == "Unknown (MADE_UP_STATE)"


def test_existing_sm_disconnect_and_assoc_still_work():
    events = parse_wifi_events(_section(FIXTURE))
    disc = [e for e in events if e.kind == "disconnection"]
    assert len(disc) == 1
    assert disc[0].reason_code == 15 and disc[0].reason_name == "4-way handshake timeout"
    assert disc[0].locally_generated is False
    assoc = [e for e in events if e.kind == "association"]
    assert len(assoc) == 1 and assoc[0].roam is True


def test_supplicant_auth_path_and_disconnect_state():
    events = parse_wifi_events(_section(FIXTURE, line_start=50))
    supp = [e for e in events if e.kind == "supplicant_state"]
    names = [e.reason_name for e in supp]
    assert names == [
        "ASSOCIATING", "ASSOCIATED", "FOUR_WAY_HANDSHAKE", "COMPLETED",
        "DISCONNECTED", "Unknown (MADE_UP_STATE)",
    ]
    assert all(e.ssid == LAB_SSID for e in supp if e.reason_name != "DISCONNECTED" or True)
    assert all(e.source_ref.section == "wifi" and e.source_ref.line_start >= 50 for e in supp)


def test_network_connection_and_dhcp_ip_success():
    events = parse_wifi_events(_section(FIXTURE))
    net = [e for e in events if e.kind == "network_connection"]
    assert len(net) == 1
    assert net[0].ssid == LAB_SSID and net[0].bssid == LAB_BSSID

    dhcp = [e for e in events if e.kind == "dhcp"]
    assert {e.reason_name for e in dhcp} >= {"pre_dhcp_action", "post_dhcp_action"}

    assert any(e.kind == "ip_provisioning" and e.reason_name == "success" for e in events)
    assert any(e.kind == "ip_configuration" and e.reason_name == "successful" for e in events)


def test_unparsed_what_types_ignored():
    events = parse_wifi_events(_section(FIXTURE))
    assert not any("CMD_UPDATE_AP_CAPABILITY" in (e.reason_name or "") for e in events)
    # only the kinds we intentionally decode
    assert set(e.kind for e in events) <= {
        "disconnection", "association", "supplicant_state",
        "network_connection", "dhcp", "ip_provisioning", "ip_configuration",
    }


def test_unknown_80211_reason_unchanged():
    assert _reason_name(999) == "Unknown (802.11 reason 999)"
