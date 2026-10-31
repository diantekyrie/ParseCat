"""Real protocol-level analysis of packet captures, on top of the
container-metadata-only PacketCaptureSummary in pcap.py.

Two backends, tried in this order:

1. tshark (subprocess) -- full Wireshark dissection, used whenever `tshark`
   is on PATH. This is the industry-standard tool for packet dissection
   (see the exchange this was scoped from: Wireshark/tshark's dissection
   engine is what nearly every serious network-analysis tool either shells
   out to or embeds, rather than reimplementing dissection by hand). Still
   Live-verified against real Wireshark/tshark 4.4.x (issues #67-#69 and
   the gated synthetic-fixture test in test_packet_analysis.py). That
   verification caught: an obsolete field name that made every tshark
   invocation hard-fail (`wlan_mgt.fixed.reason_code` ->
   `wlan.fixed.reason_code`), a stale boolean comparison that silently
   dropped every TCP RST on this backend (`tcp.flags.reset == "1"` never
   matches tshark's `"True"`/`"False"` text), the same boolean trap on
   `wlan.fc.retry` (retry_count/rate stayed 0.0), and an undecoded SSID
   (wlan.ssid is FT_BYTES; `-T fields` emits raw hex, not the network
   name). Unit tests mock `_run_tshark_fields` row shapes; a
   `@pytest.mark.skipif(not tshark_available())` live test exercises the
   real binary when present.

2. Fallback (no external dependency) -- used when tshark isn't available.
   This is NOT generic scapy packet dissection: that was benchmarked
   against a real 297,262-packet 802.11 monitor capture and found far too
   slow (>120s just to construct a RadioTap object per packet, one layer,
   with no full protocol stack). Instead this hand-rolls the radiotap and
   802.11 MAC header parsing directly from raw bytes -- the same low-level,
   verified-against-real-bytes approach already used for the classic
   btsnoop format in bt_hci.py. The hand-rolled RSSI (dBm Antenna Signal)
   extraction was checked byte-for-byte against scapy's own
   RadioTap.dBm_AntSignal decoding on a real capture (0 mismatches across
   3000 packets) before being trusted for a full-file run, which then
   completes in ~2s instead of >120s.

   Ethernet/IP-linktype captures (not 802.11 monitor mode) use scapy for
   real dissection instead of a hand-rolled IP/TCP/DNS parser -- those
   captures are typically orders of magnitude smaller than a promiscuous
   Wi-Fi monitor capture (which captures every nearby device's traffic,
   not just one device's), so scapy's per-packet overhead is acceptable
   there. A packet-count safety cap still applies in case that assumption
   is wrong for a given file.

Gap-matrix decisions (issue #70, PC-pcap-004):
  * 802.11 deauth/disassoc reason codes: now decoded on BOTH backends.
    tshark already reported them (issue #67); the fallback's 24-byte
    non-QoS/non-4-address MAC header is immediately followed by the
    Reason Code as the frame body's ONLY fixed field for these two
    subtypes (no IEs), so it's a simple, deterministic 2-byte read --
    low risk, same confidence as any other directly-parsed field. Names
    come from wifi.py's REASON_CODE_NAMES (one shared table, not a
    second copy that could drift from it).
  * TCP retransmission: tshark-only, permanently. tshark computes this
    from its own full bidirectional stream/ACK tracking; hand-rolling an
    equivalent on either fallback (no TCP stream state on the 802.11
    path at all, and only single-pass per-packet scapy dissection on the
    Ethernet path) would mean inventing a retransmission heuristic this
    project has no way to verify against tshark's own analysis -- against
    the "invent nothing" rule the rest of this parser follows. Each
    fallback's `note` field says so explicitly.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from app.parsers.base import PacketAnalysis, PacketAnomalyEvent, PacketFrameTypeStat, PacketIdentitySignal
from app.parsers.wifi import _reason_name

# ---------------------------------------------------------------------------
# Shared 802.11 constants
# ---------------------------------------------------------------------------

DOT11_MGMT_SUBTYPES = {
    0: "Association Request", 1: "Association Response",
    2: "Reassociation Request", 3: "Reassociation Response",
    4: "Probe Request", 5: "Probe Response",
    8: "Beacon", 9: "ATIM", 10: "Disassociation",
    11: "Authentication", 12: "Deauthentication", 13: "Action",
}
DOT11_CTRL_SUBTYPES = {
    7: "Control Wrapper", 8: "Block Ack Request", 9: "Block Ack",
    10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK", 14: "CF-End",
    15: "CF-End + CF-Ack",
}
DOT11_DATA_SUBTYPES = {
    0: "Data", 4: "Null (no data)", 8: "QoS Data", 12: "QoS Null (no data)",
}
DOT11_TYPE_TABLES = {0: DOT11_MGMT_SUBTYPES, 1: DOT11_CTRL_SUBTYPES, 2: DOT11_DATA_SUBTYPES}


def dot11_frame_label(ftype: int, subtype: int) -> str:
    table = DOT11_TYPE_TABLES.get(ftype)
    name = table.get(subtype) if table else None
    if name:
        return name
    type_name = {0: "Management", 1: "Control", 2: "Data"}.get(ftype, f"Type {ftype}")
    return f"{type_name} (subtype {subtype})"


def is_supported_link_layer_pcap(linktype: int) -> str:
    if linktype in (105, 127):  # IEEE 802.11 / Radiotap-wrapped 802.11
        return "802.11"
    if linktype == 1:  # Ethernet
        return "ethernet"
    return "unknown"


# ---------------------------------------------------------------------------
# tshark backend
# ---------------------------------------------------------------------------

# wlan.fc.type and wlan.fc.subtype are requested as separate fields, not the
# combined wlan.fc.type_subtype -- that field's exact output format wasn't
# something to guess at without a live tshark to check against.
TSHARK_FIELDS = [
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry",
    "radiotap.dbm_antsignal", "wlan.ssid", "wlan.bssid",
    # wlan_mgt.fixed.reason_code was Wireshark's pre-4.x field name; it no
    # longer exists (confirmed against `tshark -G fields` on 4.4.18) and an
    # unknown -e field aborts the ENTIRE invocation with exit 1 -- not just
    # a missing reason code, but tshark never running at all, silently
    # falling back for every capture regardless of link layer (issue #67).
    "wlan.fixed.reason_code", "frame.time_epoch",
    "ip.src", "ip.dst", "tcp.flags.reset", "dns.qry.name",
    # #70: tshark's own stream/ACK-tracking analysis, not a heuristic this
    # project invents -- see the module docstring's gap-matrix decision.
    "tcp.analysis.retransmission",
]


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _tshark_bool(raw: str) -> bool:
    # Modern tshark emits boolean fields as "True"/"False" text; older
    # builds used "1"/"0". Accept both so tcp.flags.reset and wlan.fc.retry
    # (issues #68 + review on #80) never silently under-count.
    return raw in ("1", "True", "true")


def _decode_tshark_ssid(raw: str) -> str | None:
    # wlan.ssid is Wireshark's FT_BYTES field type -- `-T fields` emits the
    # raw SSID bytes as a hex string (observed as plain hex with no colon
    # separators on 4.4.18, e.g. "53594e54..."), not a decoded network
    # name. The fallback backend already decodes SSIDs to UTF-8 with
    # errors="replace" (see _dot11_ssid_from_ies); match that behavior
    # here (issue #69) instead of surfacing raw hex to the UI/LLM.
    # Hidden/wildcard beacons: tshark may emit "" or the literal
    # "<MISSING>" for a zero-length SSID tag -- treat both as absent
    # (fallback returns None when tag_len == 0).
    if not raw or raw == "<MISSING>":
        return None
    hex_str = raw.replace(":", "")
    try:
        return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
    except ValueError:
        # Unexpected shape (not valid hex) -- surface the raw value rather
        # than silently dropping the SSID.
        return raw


def _run_tshark_fields(path: Path) -> list[list[str]]:
    args = ["tshark", "-r", str(path), "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for f in TSHARK_FIELDS:
        args += ["-e", f]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=600, check=True)
    return [line.split("|") for line in proc.stdout.splitlines() if line]


def analyze_with_tshark(path: Path, link_layer: str) -> PacketAnalysis:
    rows = _run_tshark_fields(path)
    frame_counts: dict[str, int] = {}
    ssid_counts: dict[str, int] = {}
    bssid_counts: dict[str, int] = {}
    dns_counts: dict[str, int] = {}
    anomalies: list[PacketAnomalyEvent] = []
    rssis: list[int] = []
    retry_count = 0
    packets_with_type_subtype = 0

    for row in rows:
        (wlan_type, wlan_subtype, retry, dbm, ssid, bssid,
         reason_code, ts, ip_src, ip_dst, tcp_rst, dns_qry,
         tcp_retrans) = (row + [""] * 13)[:13]

        if wlan_type and wlan_subtype:
            try:
                ftype, subtype = int(wlan_type, 0), int(wlan_subtype, 0)
            except ValueError:
                ftype = subtype = None
            if ftype is not None and subtype is not None:
                label = dot11_frame_label(ftype, subtype)
                frame_counts[label] = frame_counts.get(label, 0) + 1
                packets_with_type_subtype += 1
                if ftype == 0 and subtype == 12:
                    anomalies.append(PacketAnomalyEvent(
                        timestamp=ts or None, kind="deauthentication",
                        detail=f"Deauthentication frame, reason code {reason_code or 'unknown'}",
                        mac_or_ip=bssid or None,
                    ))
                elif ftype == 0 and subtype == 10:
                    anomalies.append(PacketAnomalyEvent(
                        timestamp=ts or None, kind="disassociation",
                        detail=f"Disassociation frame, reason code {reason_code or 'unknown'}",
                        mac_or_ip=bssid or None,
                    ))
        if _tshark_bool(retry):
            retry_count += 1
        if dbm:
            try:
                rssis.append(int(dbm))
            except ValueError:
                pass
        decoded_ssid = _decode_tshark_ssid(ssid) if ssid else None
        if decoded_ssid:
            ssid_counts[decoded_ssid] = ssid_counts.get(decoded_ssid, 0) + 1
        if bssid:
            bssid_counts[bssid] = bssid_counts.get(bssid, 0) + 1
        if dns_qry:
            dns_counts[dns_qry] = dns_counts.get(dns_qry, 0) + 1
        # Modern tshark emits boolean fields as "True"/"False" text, not
        # "1"/"0" -- comparing only against "1" meant TCP RST was silently
        # never detected on the tshark backend at all (issue #68). Same
        # helper covers wlan.fc.retry above.
        if _tshark_bool(tcp_rst):
            anomalies.append(PacketAnomalyEvent(
                timestamp=ts or None, kind="tcp_reset",
                detail=f"TCP RST {ip_src or '?'} -> {ip_dst or '?'}",
                mac_or_ip=ip_src or None,
            ))
        # #70: tcp.analysis.retransmission is tshark's own per-packet verdict
        # from its stream/ACK tracking -- same boolean-text trap as retry and
        # RST above, so it needs the same _tshark_bool helper.
        if _tshark_bool(tcp_retrans):
            anomalies.append(PacketAnomalyEvent(
                timestamp=ts or None, kind="tcp_retransmission",
                detail=f"TCP retransmission {ip_src or '?'} -> {ip_dst or '?'}",
                mac_or_ip=ip_src or None,
            ))

    identity_signals = (
        [PacketIdentitySignal("ssid", k, v) for k, v in ssid_counts.items()]
        + [PacketIdentitySignal("bssid", k, v) for k, v in bssid_counts.items()]
        + [PacketIdentitySignal("dns_query", k, v) for k, v in dns_counts.items()]
    )

    return PacketAnalysis(
        backend="tshark",
        packets_analyzed=len(rows),
        link_layer=link_layer,
        frame_type_breakdown=[PacketFrameTypeStat(k, v) for k, v in sorted(frame_counts.items(), key=lambda kv: -kv[1])],
        retry_count=retry_count if packets_with_type_subtype else None,
        retry_rate_pct=(round(100 * retry_count / packets_with_type_subtype, 2) if packets_with_type_subtype else None),
        rssi_min_dbm=min(rssis) if rssis else None,
        rssi_max_dbm=max(rssis) if rssis else None,
        rssi_avg_dbm=(round(sum(rssis) / len(rssis), 1) if rssis else None),
        identity_signals=identity_signals,
        anomalies=anomalies[:200],
        note=(
            "Full tshark dissection. Deauthentication/disassociation reason codes, "
            "TCP resets, and TCP retransmissions are all real per-packet facts from "
            "tshark's own stream analysis."
        ),
    )


# ---------------------------------------------------------------------------
# Fallback backend: hand-rolled radiotap/802.11 header parser
# ---------------------------------------------------------------------------

# Size/alignment (bytes) for radiotap present-bit fields 0-4, in field-definition
# order. Only fields 0-4 are needed to compute field 5's (dBm Antenna Signal)
# byte offset, since present bits map to fixed field-definition slots regardless
# of which higher-numbered fields are also present -- see PacketAnalysis
# docstring for how this was verified against scapy's own decoding.
_RADIOTAP_FIELD_0_4 = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (4, 2), 4: (2, 2)}


def _radiotap_rssi_and_header_len(pkt: bytes) -> tuple[int | None, int | None]:
    if len(pkt) < 8:
        return None, None
    _vers, _pad, rt_len, present1 = struct.unpack("<BBHI", pkt[0:8])
    offset = 8
    p = present1
    while p & 0x80000000:
        if offset + 4 > len(pkt):
            return None, rt_len
        p = struct.unpack("<I", pkt[offset:offset + 4])[0]
        offset += 4

    field_off = offset
    for bit in range(5):
        if present1 & (1 << bit):
            size, align = _RADIOTAP_FIELD_0_4[bit]
            if field_off % align:
                field_off += align - (field_off % align)
            field_off += size

    rssi = None
    if (present1 & (1 << 5)) and field_off < len(pkt):
        val = pkt[field_off]
        rssi = val - 256 if val >= 128 else val
    return rssi, rt_len


def _dot11_frame_control(pkt: bytes, dot11_start: int) -> tuple[int, int, bool] | None:
    if dot11_start + 2 > len(pkt):
        return None
    fc0, fc1 = pkt[dot11_start], pkt[dot11_start + 1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xF
    retry = bool(fc1 & 0x08)
    return ftype, subtype, retry


def _dot11_addr2(pkt: bytes, dot11_start: int, ftype: int) -> str | None:
    # addr2 (transmitter address) for management frames. This IS the BSSID
    # when the frame is a beacon/probe-response (only an AP sends those).
    # For a deauth/disassoc frame it's just whichever side sent it -- an AP
    # deauthenticating a client, or a client deauthenticating itself from
    # an AP -- so callers must not assume "BSSID" for that case; it's
    # reported generically as the event's associated MAC address instead.
    # Fixed offset for the common (non-QoS, non-4-address) management
    # header shape: FC(2) + Duration(2) + addr1(6) + addr2(6).
    if ftype != 0:
        return None
    off = dot11_start + 2 + 2 + 6
    if off + 6 > len(pkt):
        return None
    mac = pkt[off:off + 6]
    return ":".join(f"{b:02x}" for b in mac)


def _dot11_reason_code(pkt: bytes, dot11_start: int) -> int | None:
    # #70 / Arch review on #115: for Deauthentication and Disassociation
    # frames, the frame body is the Reason Code field ALONE (2 bytes,
    # little-endian) -- no other fixed fields, no IEs -- immediately after
    # the same 24-byte non-QoS/non-4-address management header used by
    # _dot11_addr2 above: FC(2) + Duration(2) + addr1(6) + addr2(6) +
    # addr3(6) + SeqCtrl(2). But that only holds for a plaintext frame with
    # no +HT Control field:
    #   * Protected bit (FC byte 1, 0x40) -- under 802.11w/PMF, deauth/
    #     disassoc sent after association are encrypted: the body starts
    #     with a CCMP/GCMP header, not the reason code. Reading these 2
    #     bytes would decode ciphertext as a confident-looking (wrong)
    #     reason -- exactly the fabricated fact this parser must not
    #     produce, so return None rather than guess.
    #   * Order bit (FC byte 1, 0x80) -- adds a 4-byte +HT Control field
    #     between SeqCtrl and the frame body, shifting the reason code.
    # addr2's offset is unaffected by either bit -- it's part of the fixed
    # MAC header, before SeqCtrl/+HTC/body -- so _dot11_addr2 needs no
    # equivalent guard.
    if dot11_start + 2 > len(pkt):
        return None
    fc_byte1 = pkt[dot11_start + 1]
    if fc_byte1 & 0x40:  # Protected Frame
        return None
    off = dot11_start + 2 + 2 + 6 + 6 + 6 + 2
    if fc_byte1 & 0x80:  # Order (+HT Control present)
        off += 4
    if off + 2 > len(pkt):
        return None
    return struct.unpack("<H", pkt[off:off + 2])[0]


def _dot11_ssid_from_ies(pkt: bytes, dot11_start: int) -> str | None:
    # Beacon/probe-response fixed fields: Timestamp(8) + Beacon Interval(2) +
    # Capability Info(2) = 12 bytes, then tagged parameters begin. Tag 0 = SSID.
    ie_start = dot11_start + 2 + 2 + 6 + 6 + 6 + 2 + 12
    if ie_start >= len(pkt):
        return None
    off = ie_start
    while off + 2 <= len(pkt):
        tag, tag_len = pkt[off], pkt[off + 1]
        val_start = off + 2
        if val_start + tag_len > len(pkt):
            return None
        if tag == 0:
            if tag_len == 0:
                return None  # hidden/broadcast SSID
            try:
                return pkt[val_start:val_start + tag_len].decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                return None
        off = val_start + tag_len
    return None


def _analyze_dot11_fallback(path: Path) -> PacketAnalysis:
    from scapy.utils import RawPcapReader

    frame_counts: dict[str, int] = {}
    ssid_counts: dict[str, int] = {}
    bssid_counts: dict[str, int] = {}
    anomalies: list[PacketAnomalyEvent] = []
    rssis: list[int] = []
    retry_count = 0
    packets_analyzed = 0

    with RawPcapReader(str(path)) as reader:
        for pkt_data, _meta in reader:
            pkt = bytes(pkt_data)
            packets_analyzed += 1
            rssi, rt_len = _radiotap_rssi_and_header_len(pkt)
            if rssi is not None:
                rssis.append(rssi)
            if rt_len is None:
                continue
            parsed = _dot11_frame_control(pkt, rt_len)
            if not parsed:
                continue
            ftype, subtype, retry = parsed
            label = dot11_frame_label(ftype, subtype)
            frame_counts[label] = frame_counts.get(label, 0) + 1
            if retry:
                retry_count += 1

            if ftype == 0 and subtype in (5, 8):  # Probe Response, Beacon
                ssid = _dot11_ssid_from_ies(pkt, rt_len)
                if ssid:
                    ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1
                bssid = _dot11_addr2(pkt, rt_len, ftype)
                if bssid:
                    bssid_counts[bssid] = bssid_counts.get(bssid, 0) + 1
            elif ftype == 0 and subtype in (10, 12):  # Disassoc, Deauth
                bssid = _dot11_addr2(pkt, rt_len, ftype)
                reason_code = _dot11_reason_code(pkt, rt_len)
                if reason_code is None:
                    detail = f"{dot11_frame_label(ftype, subtype)} frame (reason code not present in this packet)"
                else:
                    detail = (
                        f"{dot11_frame_label(ftype, subtype)} frame, reason code "
                        f"{reason_code} ({_reason_name(reason_code)})"
                    )
                anomalies.append(PacketAnomalyEvent(
                    timestamp=None,
                    kind="deauthentication" if subtype == 12 else "disassociation",
                    detail=detail,
                    mac_or_ip=bssid,
                ))

    identity_signals = (
        [PacketIdentitySignal("ssid", k, v) for k, v in ssid_counts.items()]
        + [PacketIdentitySignal("bssid", k, v) for k, v in bssid_counts.items()]
    )
    typed = sum(frame_counts.values())

    return PacketAnalysis(
        backend="fallback",
        packets_analyzed=packets_analyzed,
        link_layer="802.11",
        frame_type_breakdown=[PacketFrameTypeStat(k, v) for k, v in sorted(frame_counts.items(), key=lambda kv: -kv[1])],
        retry_count=retry_count if typed else None,
        retry_rate_pct=(round(100 * retry_count / typed, 2) if typed else None),
        rssi_min_dbm=min(rssis) if rssis else None,
        rssi_max_dbm=max(rssis) if rssis else None,
        rssi_avg_dbm=(round(sum(rssis) / len(rssis), 1) if rssis else None),
        identity_signals=identity_signals,
        anomalies=anomalies[:200],
        note=(
            "Hand-rolled radiotap/802.11 header parser (tshark not available). Frame "
            "type/subtype, retry flag, RSSI, and deauthentication/disassociation "
            "reason codes are exact per-packet facts. No TCP/retransmission analysis "
            "is attempted on this 802.11 monitor-mode path -- that stays tshark-only "
            "by design, not a gap to be closed here."
        ),
    )


def _analyze_ethernet_fallback(path: Path) -> PacketAnalysis:
    from scapy.utils import RawPcapReader
    from scapy.layers.inet import IP, TCP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import Ether

    MAX_PACKETS = 50_000  # safety cap; scapy per-packet dissection is fine at
    # normal (non-monitor-mode) capture sizes but this protects against an
    # unexpectedly huge Ethernet capture stalling a request.

    frame_counts: dict[str, int] = {}
    dns_counts: dict[str, int] = {}
    anomalies: list[PacketAnomalyEvent] = []
    packets_analyzed = 0
    truncated = False

    with RawPcapReader(str(path)) as reader:
        for pkt_data, _meta in reader:
            if packets_analyzed >= MAX_PACKETS:
                truncated = True
                break
            packets_analyzed += 1
            pkt = Ether(bytes(pkt_data))
            if pkt.haslayer(TCP):
                frame_counts["TCP"] = frame_counts.get("TCP", 0) + 1
                tcp = pkt[TCP]
                if tcp.flags.R:
                    ip = pkt[IP] if pkt.haslayer(IP) else None
                    anomalies.append(PacketAnomalyEvent(
                        timestamp=None, kind="tcp_reset",
                        detail=f"TCP RST {ip.src if ip else '?'} -> {ip.dst if ip else '?'}",
                        mac_or_ip=ip.src if ip else None,
                    ))
            elif pkt.haslayer("UDP"):
                frame_counts["UDP"] = frame_counts.get("UDP", 0) + 1
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    dns_counts[qname] = dns_counts.get(qname, 0) + 1
                except Exception:  # noqa: BLE001
                    pass

    note = (
        "scapy-based Ethernet/IP dissection (tshark not available). "
        "TCP retransmission analysis stays tshark-only by design, not a gap "
        "to be closed here."
    )
    if truncated:
        note += f" Capped at the first {MAX_PACKETS} packets -- this capture is larger than that."

    return PacketAnalysis(
        backend="fallback",
        packets_analyzed=packets_analyzed,
        link_layer="ethernet",
        frame_type_breakdown=[PacketFrameTypeStat(k, v) for k, v in sorted(frame_counts.items(), key=lambda kv: -kv[1])],
        retry_count=None,
        retry_rate_pct=None,
        rssi_min_dbm=None,
        rssi_max_dbm=None,
        rssi_avg_dbm=None,
        identity_signals=[PacketIdentitySignal("dns_query", k, v) for k, v in dns_counts.items()],
        anomalies=anomalies[:200],
        note=note,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_packet_capture(
    path: Path, linktype: int, warnings: list[str] | None = None,
) -> PacketAnalysis | None:
    link_layer = is_supported_link_layer_pcap(linktype)
    if link_layer == "unknown":
        return None

    if tshark_available():
        try:
            return analyze_with_tshark(path, link_layer)
        except Exception as exc:  # noqa: BLE001 -- fall back rather than fail the whole upload
            if warnings is not None:
                warnings.append(f"tshark packet analysis failed, using fallback: {exc}")

    if link_layer == "802.11":
        return _analyze_dot11_fallback(path)
    return _analyze_ethernet_fallback(path)
