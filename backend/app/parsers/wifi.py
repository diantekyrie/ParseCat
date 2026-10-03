"""Parser for `DUMP OF SERVICE wifi` -> WifiController/ClientModeImpl's
state-machine transition log:

    rec[160]: time=08-13 16:11:28.243 processed=L3ConnectedState org=L3ConnectedState
      dest=DisconnectedState what=NETWORK_DISCONNECTION_EVENT screen=off
      ssid: "pixel_simhouse" bssid: bc:df:58:b8:23:4b reasonCode: 0 locallyGenerated: false

    rec[3]: time=08-13 14:21:06.986 processed=L2ConnectedState org=L3ConnectedState
      dest=<null> what=ASSOCIATED_BSSID_EVENT screen=off 0 0 BSSID=bc:df:58:b8:1d:51
      Target Bssid=any Last Bssid=bc:df:58:b8:1d:51 roam=false

Only NETWORK_DISCONNECTION_EVENT (with its 802.11 reason code) and
ASSOCIATED_BSSID_EVENT (with its roam flag) are decoded -- the state
machine log has dozens of other `what=` event types (AP capability
updates, screen state, scan requests, ...) that carry no
connectivity-failure signal and aren't parsed here.
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
    10: "Disassociated: unacceptable Power Capability element",
    11: "Disassociated: unacceptable Supported Channels element",
    12: "Reserved",
    13: "Invalid information element",
    14: "Message integrity code (MIC) failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "IE in 4-way handshake differs from association request",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSN information element version",
    22: "Invalid RSN information element capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    25: "Reserved",
    26: "Reserved",
    27: "Reserved",
    28: "Reserved",
    29: "Reserved",
    30: "Reserved",
    31: "Reserved",
    32: "Disassociated for unspecified QoS-related reason",
    33: "Disassociated: QoS AP lacks sufficient bandwidth",
    34: "Disassociated due to excessive frame loss / weak signal",
}


def _reason_name(code: int) -> str:
    return REASON_CODE_NAMES.get(code, f"Unknown (802.11 reason {code})")


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

    return out
