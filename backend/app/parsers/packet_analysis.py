"""Real protocol-level analysis of packet captures, on top of the
container-metadata-only PacketCaptureSummary in pcap.py.

Two backends, tried in this order:

1. tshark (subprocess) -- full Wireshark dissection, used whenever `tshark`
   is on PATH. This is the industry-standard tool for packet dissection
   (see the exchange this was scoped from: Wireshark/tshark's dissection
   engine is what nearly every serious network-analysis tool either shells
   out to or embeds, rather than reimplementing dissection by hand). NOT
   live-verified in this codebase's dev/test environment -- `tshark` isn't
   installed there (confirmed: `shutil.which("tshark")` returns None, and
   installing it here requires admin rights this environment doesn't have).
   Verify against a real capture the first time this path actually runs
   somewhere tshark is present.

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
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

from app.parsers.base import PacketAnalysis, PacketAnomalyEvent, PacketFrameTypeStat, PacketIdentitySignal

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
    "wlan_mgt.fixed.reason_code", "frame.time_epoch",
    "ip.src", "ip.dst", "tcp.flags.reset", "dns.qry.name",
]


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


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
         reason_code, ts, ip_src, ip_dst, tcp_rst, dns_qry) = (row + [""] * 12)[:12]

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
        if retry == "1":
            retry_count += 1
        if dbm:
            try:
                rssis.append(int(dbm))
            except ValueError:
                pass
        if ssid:
            ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1
        if bssid:
            bssid_counts[bssid] = bssid_counts.get(bssid, 0) + 1
        if dns_qry:
            dns_counts[dns_qry] = dns_counts.get(dns_qry, 0) + 1
        if tcp_rst == "1":
            anomalies.append(PacketAnomalyEvent(
                timestamp=ts or None, kind="tcp_reset",
                detail=f"TCP RST {ip_src or '?'} -> {ip_dst or '?'}",
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
            "Full tshark dissection. Deauthentication/disassociation reason codes and "
            "TCP resets are real per-packet facts; TCP retransmission analysis is not "
            "included in this pass."
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
                anomalies.append(PacketAnomalyEvent(
                    timestamp=None,
                    kind="deauthentication" if subtype == 12 else "disassociation",
                    detail=f"{dot11_frame_label(ftype, subtype)} frame (reason code not decoded in this backend)",
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
            "type/subtype, retry flag, and RSSI are exact per-packet facts. "
            "Deauthentication/disassociation reason codes are NOT decoded in this "
            "backend (would need the management-frame fixed-parameters region parsed "
            "further); no TCP/retransmission analysis is attempted here at all."
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
        "No TCP retransmission analysis in this backend."
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
