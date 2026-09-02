import struct

from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import Capture, Investigation, InvestigationCaptureLink, PacketCaptureSummaryRow
from app.parsers.pcap import parse_pcap
from app.parsers.base import ParsedCapture
from app.services.ingestion import _decode_txt_upload, parse_bugreport_txt
from app.services.persistence import persist_capture
from app.services.summary import build_capture_summary


def test_decode_txt_upload_sniffs_utf16_bom():
    # Found live: a real `adb logcat -v threadtime > out.txt` capture came
    # through as UTF-16 LE with a BOM -- PowerShell's `>` redirect defaults
    # to that encoding on Windows, not UTF-8. Decoding it as UTF-8 with
    # errors="replace" doesn't raise; it silently mangles every other byte
    # into a replacement character, so the failure never surfaces as an
    # error, only as an empty, unexplained result downstream.
    text = "09-02 01:31:53.866  1145  1145 D keystore2: hello"
    utf16le = b"\xff\xfe" + text.encode("utf-16-le")
    utf16be = b"\xfe\xff" + text.encode("utf-16-be")
    utf8_bom = b"\xef\xbb\xbf" + text.encode("utf-8")
    plain_utf8 = text.encode("utf-8")

    assert _decode_txt_upload(utf16le) == text
    assert _decode_txt_upload(utf16be) == text
    assert _decode_txt_upload(utf8_bom) == text
    assert _decode_txt_upload(plain_utf8) == text


def test_plain_logcat_txt_gets_one_clear_diagnosis_not_ten_warnings(tmp_path):
    # A raw `adb logcat -v threadtime` dump has no "DUMP OF SERVICE .../
    # ------ SECTION ------" markers anywhere -- those only exist in a full
    # bugreport. Before this fix, that produced 10+ generic "no X section
    # found" warnings (one per section ParseCat looks for) with nothing
    # explaining WHY none were found. It also silently swallowed the
    # entire file into an unterminated "preamble" section (PREAMBLE has no
    # delimiter of its own, so it never stops accumulating lines without a
    # real header to end it on) -- not empty, but not useful data either,
    # and both cases need the same single, clear diagnosis.
    logcat_lines = "\n".join(
        f"09-02 01:31:5{i}.866  1145  1145 D keystore2: some debug line {i}"
        for i in range(10)
    )
    p = tmp_path / "logcat.txt"
    p.write_bytes(b"\xff\xfe" + logcat_lines.encode("utf-16-le"))

    capture = parse_bugreport_txt(p)
    assert len(capture.parse_warnings) == 1
    assert "plain logcat capture" in capture.parse_warnings[0]
    assert "adb bugreport" in capture.parse_warnings[0]


def test_unrecognizable_txt_gets_a_different_diagnosis_than_logcat(tmp_path):
    p = tmp_path / "not_a_bugreport.txt"
    p.write_text("just some random notes, not a log file at all\nsecond line\n")

    capture = parse_bugreport_txt(p)
    assert len(capture.parse_warnings) == 1
    assert "logcat" not in capture.parse_warnings[0]
    assert "No recognized bugreport section markers" in capture.parse_warnings[0]


def _classic_pcap() -> bytes:
    header = b"\xd4\xc3\xb2\xa1" + struct.pack(
        "<HHiiii",
        2,      # major
        4,      # minor
        0,      # thiszone
        0,      # sigfigs
        65535,  # snaplen
        1,      # Ethernet
    )
    pkt1 = struct.pack("<IIII", 1_800_000_000, 123456, 4, 4) + b"abcd"
    pkt2 = struct.pack("<IIII", 1_800_000_001, 0, 2, 4) + b"ef"
    return header + pkt1 + pkt2


def _block(endian: str, block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack(endian + "II", block_type, total_len) + body + struct.pack(endian + "I", total_len)


def _pcapng() -> bytes:
    endian = "<"
    section = _block(
        endian,
        0x0A0D0D0A,
        b"\x4d\x3c\x2b\x1a" + struct.pack(endian + "HHq", 1, 0, -1),
    )
    interface = _block(
        endian,
        0x00000001,
        struct.pack(endian + "HHI", 1, 0, 65535),
    )
    packet_data = b"abcd"
    timestamp = 1_800_000_000_000_000
    packet = _block(
        endian,
        0x00000006,
        struct.pack(
            endian + "IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet_data),
            len(packet_data),
        )
        + packet_data,
    )
    return section + interface + packet


def test_parse_classic_pcap_summary():
    summary = parse_pcap(_classic_pcap())

    assert summary.format == "pcap"
    assert summary.linktype_name == "Ethernet"
    assert summary.total_packets == 2
    assert summary.captured_bytes == 6
    assert summary.original_bytes == 8
    assert summary.truncated_packets == 1
    assert summary.malformed_packets == 0
    assert summary.first_timestamp is not None
    assert summary.last_timestamp is not None


def test_parse_pcapng_summary():
    summary = parse_pcap(_pcapng())

    assert summary.format == "pcapng"
    assert summary.linktype_name == "Ethernet"
    assert summary.total_packets == 1
    assert summary.captured_bytes == 4
    assert summary.original_bytes == 4
    assert summary.truncated_packets == 0
    assert summary.malformed_packets == 0
    assert summary.first_timestamp is not None


def test_investigation_groups_multiple_captures():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        first = ParsedCapture()
        first.packet_capture_summary = parse_pcap(_classic_pcap())
        cap1 = persist_capture(session, "local-device", "trace.pcap", first, investigation_label="hotel-wifi-drop")
        cap2 = persist_capture(session, "local-device", "bugreport.txt", ParsedCapture(), investigation_label="hotel-wifi-drop")

        investigation = session.exec(
            select(Investigation).where(Investigation.label == "hotel-wifi-drop")
        ).one()
        links = session.exec(
            select(InvestigationCaptureLink).where(
                InvestigationCaptureLink.investigation_id == investigation.id
            )
        ).all()

        assert {link.capture_id for link in links} == {cap1.id, cap2.id}
        assert session.exec(select(Capture)).all()
        assert session.exec(select(PacketCaptureSummaryRow)).one().total_packets == 2
        assert build_capture_summary(session, cap1.id)["packet_capture_summary"]["total_packets"] == 2
