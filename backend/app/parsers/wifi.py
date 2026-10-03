"""Parser for `DUMP OF SERVICE wifi` -> WifiController/ClientModeImpl's
state-machine transition log:

    rec[160]: time=08-13 16:11:28.243 processed=L3ConnectedState org=L3ConnectedState
      dest=DisconnectedState what=NETWORK_DISCONNECTION_EVENT screen=off
      ssid: "pixel_simhouse" bssid: bc:df:58:b8:23:4b reasonCode: 0 locallyGenerated: false

    rec[3]: time=08-13 14:21:06.986 processed=L2ConnectedState org=L3ConnectedState
      dest=<null> what=ASSOCIATED_BSSID_EVENT screen=off 0 0 BSSID=bc:df:58:b8:1d:51
      Target Bssid=any Last Bssid=bc:df:58:b8:1d:51 roam=false

    rec[4]: time=08-13 14:21:06.993 ... what=SUPPLICANT_STATE_CHANGE_EVENT ...
      ssid: "pixel_simhouse" bssid: bc:df:58:b8:1d:51 ... state: FOUR_WAY_HANDSHAKE

    rec[246]: ... what=CMD_IPV4_PROVISIONING_SUCCESS ... DhcpResultsParcelable{...}

Decodes disconnection + association (SM), plus supplicant-state /
NETWORK_CONNECTION / DHCP+IP provisioning events beyond SM disconnect.
Other `what=` types (AP capability, screen, scans, ...) are skipped.

Invent-nothing: unknown 802.11 reason codes → `Unknown (802.11 reason N)`;
unknown supplicant `state:` tokens → `Unknown (TOKEN)`. DHCP *failure*
`rec[]` shapes were not observed in local captures — not invented here
(see issue #75).
"""
from __future__ import annotations

import re

from app.parsers.base import SourceRef, WifiEvent
from app.parsers.section_extractor import Section

REC_LINE_RE = re.compile(
    r"^\s*rec\[\d+\]: time=(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) .*?what=(?P<what>\S+) (?P<rest>.*)$"
)

DISCONNECT_RE = re.compile(
    r'ssid: "(?P<ssid>[^"]*)" bssid: (?P<bssid>\S+) reasonCode: (?P<reason>\d+) '
    r"locallyGenerated: (?P<local>true|false)"
)

ASSOC_RE = re.compile(
    r"BSSID=(?P<bssid>\S+) Target Bssid=\S+ Last Bssid=\S+ roam=(?P<roam>true|false)"
)

SUPPLICANT_RE = re.compile(
    r'ssid: "(?P<ssid>[^"]*)" bssid: (?P<bssid>\S+) nid: \d+ frequencyMhz: \d+ state: (?P<state>\S+)'
)

# NETWORK_CONNECTION_EVENT rest is free-form; grab bssid + quoted ssid.
NET_CONN_RE = re.compile(
    r"(?P<bssid>[0-9a-fA-F:]{17})\s+nid=\d+\s+\"(?P<ssid>[^\"]*)\""
)

# Observed Android SupplicantState names in WifiController rec[] lines.
# Anything else stays Unknown (TOKEN) — do not invent.
# Only states observed in real WifiController rec[] lines so far.
# Additional Android SupplicantState enum values stay Unknown until seen.
KNOWN_SUPPLICANT_STATES = {
    "ASSOCIATING",
    "ASSOCIATED",
    "FOUR_WAY_HANDSHAKE",
    "COMPLETED",
    "DISCONNECTED",
    "SCANNING",
}

DHCP_IP_WHATS = {
    "CMD_PRE_DHCP_ACTION": ("dhcp", "pre_dhcp_action"),
    "CMD_PRE_DHCP_ACTION_COMPLETE": ("dhcp", "pre_dhcp_action_complete"),
    "CMD_POST_DHCP_ACTION": ("dhcp", "post_dhcp_action"),
    "CMD_IPV4_PROVISIONING_SUCCESS": ("ip_provisioning", "success"),
    "CMD_IP_CONFIGURATION_SUCCESSFUL": ("ip_configuration", "successful"),
}

# IEEE 802.11 reason codes -- the subset most relevant to diagnosing drops.
# Anything not listed here is reported as "Unknown (N)", never guessed.
REASON_CODE_NAMES = {
    0: "Reserved/unspecified",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated: station leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated: AP unable to handle all associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated: station leaving BSS",
    9: "Station requesting (re)association not authenticated",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "IE in 4-way handshake differs from association request",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    23: "IEEE 802.1X authentication failed",
    34: "Disassociated due to excessive frame loss / weak signal",
}


def _reason_name(code: int) -> str:
    return REASON_CODE_NAMES.get(code, f"Unknown (802.11 reason {code})")


def _supplicant_state_name(state: str) -> str:
    if state in KNOWN_SUPPLICANT_STATES:
        return state
    return f"Unknown ({state})"


def parse_wifi_events(section: Section) -> list[WifiEvent]:
    out: list[WifiEvent] = []
    for i, raw in enumerate(section.lines):
        m = REC_LINE_RE.match(raw)
        if not m:
            continue
        abs_line = section.line_start + i
        ref = SourceRef("wifi", abs_line, abs_line)
        what, rest, ts = m.group("what"), m.group("rest"), m.group("ts")

        if what == "NETWORK_DISCONNECTION_EVENT":
            dm = DISCONNECT_RE.search(rest)
            if dm:
                reason = int(dm.group("reason"))
                out.append(WifiEvent(
                    timestamp=ts, kind="disconnection", ssid=dm.group("ssid"),
                    bssid=dm.group("bssid"), reason_code=reason, reason_name=_reason_name(reason),
                    locally_generated=(dm.group("local") == "true"), roam=None,
                    source_ref=ref,
                ))
        elif what == "ASSOCIATED_BSSID_EVENT":
            am = ASSOC_RE.search(rest)
            if am:
                out.append(WifiEvent(
                    timestamp=ts, kind="association", ssid=None, bssid=am.group("bssid"),
                    reason_code=None, reason_name=None, locally_generated=None,
                    roam=(am.group("roam") == "true"), source_ref=ref,
                ))
        elif what == "SUPPLICANT_STATE_CHANGE_EVENT":
            sm = SUPPLICANT_RE.search(rest)
            if sm:
                state_name = _supplicant_state_name(sm.group("state"))
                out.append(WifiEvent(
                    timestamp=ts, kind="supplicant_state",
                    ssid=sm.group("ssid"), bssid=sm.group("bssid"),
                    reason_code=None, reason_name=state_name,
                    locally_generated=None, roam=None, source_ref=ref,
                ))
        elif what == "NETWORK_CONNECTION_EVENT":
            nm = NET_CONN_RE.search(rest)
            if nm:
                out.append(WifiEvent(
                    timestamp=ts, kind="network_connection",
                    ssid=nm.group("ssid"), bssid=nm.group("bssid").lower(),
                    reason_code=None, reason_name=None,
                    locally_generated=None, roam=None, source_ref=ref,
                ))
        elif what in DHCP_IP_WHATS:
            kind, outcome = DHCP_IP_WHATS[what]
            out.append(WifiEvent(
                timestamp=ts, kind=kind, ssid=None, bssid=None,
                reason_code=None, reason_name=outcome,
                locally_generated=None, roam=None, source_ref=ref,
            ))

    return out
