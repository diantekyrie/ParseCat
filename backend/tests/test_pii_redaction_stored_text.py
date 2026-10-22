"""PII scrubbing of free-text log fields before persistence.

All values are synthetic: example.com / example.org mailboxes, NANP 555-01xx
fictional numbers, Ofcom drama-range UK numbers, the textbook Luhn-valid
example IMEI 490154203237518, and made-up IMSI/ICCID/MEID digit runs. No real
capture content.
"""
from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import (
    AnrRow, BtFrameworkEventRow, CdmPairingEventRow, CrashEventRow,
    FocusEventRow, KernelLogEventRow, ProcessKillEventRow, TombstoneRow,
)
from app.parsers.base import (
    AnrFacts, BtFrameworkEvent, CdmPairingEvent, CrashEvent, FocusEvent,
    KernelLogEvent, ParsedCapture, ProcessKillEvent, SourceRef, TombstoneFacts,
)
from app.services.persistence import persist_capture
from app.services.pii_redaction import (
    ACCOUNT_TOKEN, EMAIL_TOKEN, ICCID_TOKEN, IMEI_TOKEN, IMSI_TOKEN,
    MEID_TOKEN, PHONE_TOKEN, redact_pii,
)

# ---------------------------------------------------------------- positives

@pytest.mark.parametrize("text, secret, token", [
    ("Login failed for jane.doe+test@example.com: 401", "jane.doe+test@example.com", EMAIL_TOKEN),
    ("to=<ops@mail.example.org>", "ops@mail.example.org", EMAIL_TOKEN),
    ("dialing (415) 555-0123 now", "(415) 555-0123", PHONE_TOKEN),
    ("callback 415-555-0199", "415-555-0199", PHONE_TOKEN),
    ("callback 415.555.0142.", "415.555.0142", PHONE_TOKEN),
    ("number=+1 202-555-0147 state=RINGING", "+1 202-555-0147", PHONE_TOKEN),
    ("msisdn +14155550123 ok", "+14155550123", PHONE_TOKEN),
    ("uk +44 20 7946 0958 ok", "+44 20 7946 0958", PHONE_TOKEN),
    ("uri tel:+1-415-555-0177", "415-555-0177", PHONE_TOKEN),
    ("device 49-015420-323751-8 registered", "49-015420-323751-8", IMEI_TOKEN),
    ("deviceId=490154203237518 ok", "490154203237518", IMEI_TOKEN),
    ("IMEI: 490154203237518", "490154203237518", IMEI_TOKEN),
    ("imei=35123456789012 (no luhn, keyword)", "35123456789012", IMEI_TOKEN),
    ("IMSI: 310260123456789", "310260123456789", IMSI_TOKEN),
    ("iccid=8901260123456789012F", "8901260123456789012", ICCID_TOKEN),
    ("meid=A1000012345678", "A1000012345678", MEID_TOKEN),
    ("Account {name=Jane Doe, type=com.example.chat}", "Jane Doe", ACCOUNT_TOKEN),
    ("Account {name=jdoe@example.com, type=com.google}", "jdoe@example.com", ACCOUNT_TOKEN),
    ("sync accountName=jdoe_42 authority=x", "jdoe_42", ACCOUNT_TOKEN),
])
def test_each_pii_type_is_redacted(text, secret, token):
    out = redact_pii(text)
    assert secret not in out
    assert token in out


def test_multiple_pii_in_one_crash_message():
    msg = ("java.lang.IllegalStateException: user jdoe@example.com phone "
           "(415) 555-0123 imei 490154203237518")
    out = redact_pii(msg)
    assert out == ("java.lang.IllegalStateException: user [redacted-email] phone "
                   "[redacted-phone] imei [redacted-imei]")


def test_idempotent_and_none_passthrough():
    once = redact_pii("a@example.com +14155550123")
    assert redact_pii(once) == once
    assert redact_pii(None) is None
    assert redact_pii("") == ""


# ---------------------------------------------------------------- negatives

@pytest.mark.parametrize("text", [
    # timestamps
    "10-22 12:31:00.123  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main",
    "2026-10-22T12:31:00.123456789Z",
    "2026-10-22 12:31:00+0800",
    "[ 1234.567890] init: Service 'vold' (pid 345) exited",
    "[  +0.000123] usb 1-1: new high-speed USB device",
    "epoch_ms=1761161460123 epoch_s=1761161460 elapsed=+1234ms",
    # pids / tids / uids
    "Process: com.example.app, PID: 12345",
    "pid=12345 tid=12399 uid=10234",
    # MACs
    "Connected to aa:bb:cc:dd:ee:ff reason=3",
    "BluetoothDevice 00:11:22:33:44:55 bond state 11 -> 12",
    # hex pointers / fault addrs
    "fault addr 0x0000007b2c4d1e80",
    "pc 000000000004f3a8  /apex/com.android.runtime/lib64/bionic/libc.so (abort+164)",
    "x0  0000007123456789012345  x1 0000000000000000",
    # build fingerprints / ids / versions
    "google/oriole/oriole:14/UP1A.231005.007/10754064:user/release-keys",
    "versionName=23.42.18 (190400-574239231) versionCode=234218035",
    "Linux version 5.10.198-android13-4-00050-g12f3388fd5ea",
    "android.hardware.bluetooth@1.0::IBluetoothHci/default",
    "vendor.qti.hardware.wifi@1.0-service",
    "memcpy@GLIBC_2.14",
    # package names
    "com.google.android.gms.persistent",
    "com.example.app:remote",
    # 802.11 reason text
    "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3 locally_generated=1",
    "reason 15: 4-way handshake timeout",
    # IPs and sizes
    "dhcp lease 192.168.1.23 gw 192.168.1.1",
    "allocated 1048576 bytes, rss 2147483648",
    # bare 15-digit runs are never IMEI-redacted without a keyword/format,
    # even when Luhn-valid (real capture: kernel ns timestamp passed Luhn)
    "counter 123456789012345 ticks",
    "gti.0: Drop obsolete input(IDX=1529267 IN_TS=490154203237518 TS=575859122191399 DELTA=4141506 ns)!",
    "deviceId=123456789012345",
    # Java Class@hash toString glued to a package path (real audio-focus clientId shape)
    "clientId=android.media.AudioManager$1@1a2b3c4com.example.media.player.LocalMediaPlayerController@e5e02de",
    "listener=com.example.Foo$Bar@9f8e7d6com.example.app.Player",
])
def test_non_pii_left_unchanged(text):
    assert redact_pii(text) == text


# ------------------------------------------------------------- persistence

def _ref():
    return SourceRef(section="system_log", line_start=1, line_end=1)


def test_persisted_rows_have_no_email_or_phone():
    pii = "user jdoe@example.com call (415) 555-0123 imei=490154203237518"
    parsed = ParsedCapture()
    parsed.crash_events.append(CrashEvent(
        timestamp="10-22 12:31:00.123", thread="main", package="com.example.app",
        pid=12345, exception_class="java.lang.RuntimeException", message=pii,
        root_cause_class="java.lang.IllegalStateException", root_cause_message=pii,
        root_cause_frame="com.example.app.Main.run(Main.java:42)", source_ref=_ref(),
    ))
    parsed.kernel_log_events.append(KernelLogEvent(
        boot_relative_sec=12.5, priority=3, priority_name="err", thread="kworker/0:1",
        message=pii, is_panic_family=False, source_ref=_ref(),
    ))

    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        cap = persist_capture(session, "synthetic-device", "synthetic.txt", parsed)
        crash = session.exec(select(CrashEventRow).where(CrashEventRow.capture_id == cap.id)).one()
        kern = session.exec(select(KernelLogEventRow).where(KernelLogEventRow.capture_id == cap.id)).one()

        for stored in (crash.message, crash.root_cause_message, kern.message):
            assert "jdoe@example.com" not in stored
            assert "555-0123" not in stored
            assert "490154203237518" not in stored
            assert EMAIL_TOKEN in stored and PHONE_TOKEN in stored and IMEI_TOKEN in stored
        # structured / non-free-text fields untouched
        assert crash.pid == 12345
        assert crash.package == "com.example.app"
        assert crash.root_cause_frame == "com.example.app.Main.run(Main.java:42)"
        assert kern.thread == "kworker/0:1"


def test_every_redacted_free_text_column_is_scrubbed_at_persist():
    """Covers the remaining free-text columns wired in persistence.py; MAC /
    package / pid fields on the same rows must survive untouched."""
    pii = "jdoe@example.com +14155550123"
    mac = "aa:bb:cc:dd:ee:ff"
    p = ParsedCapture()
    p.focus_events.append(FocusEvent(
        timestamp="10-22 12:31:00:123", event_type="owner_change", package="com.example.app",
        uid=10234, pid=12345, usage=None, request_result=None, loss_code=None,
        detail=pii, source_ref=_ref()))
    p.tombstones.append(TombstoneFacts(
        filename="tombstone_00", modified_at="2026-10-22 12:31", timestamp=None,
        build_fingerprint="google/oriole/oriole:14/UP1A.231005.007/10754064:user/release-keys",
        executable="/system/bin/app_process64", cmdline="com.example.app --user " + pii,
        package="com.example.app", pid=12345, tid=12345, thread_name="main", uid=10234,
        signal_number=11, signal_name="SIGSEGV", signal_code="SEGV_MAPERR",
        fault_addr="0x0000007b2c4d1e80", abi="arm64", top_frame=None))
    p.anrs.append(AnrFacts(
        filename="anr_00", timestamp=None, subject="Input dispatching timed out " + pii,
        pid=12345, package="com.example.app", reason="Input dispatching timed out " + pii,
        timeout_ms=5000, rss_kb=None))
    p.cdm_pairing_events.append(CdmPairingEvent(
        timestamp="10-22 12:31:00.123", level="I", tag="CDM_AssociationStore",
        kind="anomaly", mac_address=mac, display_name="Synthetic Watch",
        package_name="com.example.companion", association_id=7,
        detail=f"assoc {mac} owner {pii}", source_ref=_ref()))
    p.process_kills.append(ProcessKillEvent(
        timestamp="10-22 12:31:00.123", kind="kill", user_id=0, pid=12345,
        process="com.example.app", package="com.example.app", oom_adj=900,
        reason="empty " + pii, rss_kb=None, proc_state=None, source_ref=_ref()))
    p.bt_framework_events.append(BtFrameworkEvent(
        timestamp="10-22 12:31:00.123", kind="connection", action="CONNECTED",
        profile="HEADSET", address=mac, from_state=None, to_state=None,
        reason_code=None, reason_name=None, detail=f"{mac} name {pii}", source_ref=_ref()))

    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        cap = persist_capture(s, "synthetic-device", "synthetic.txt", p)
        def one(model):
            return s.exec(select(model).where(model.capture_id == cap.id)).one()
        focus, tomb, anr, cdm, kill, bt = (one(m) for m in (
            FocusEventRow, TombstoneRow, AnrRow, CdmPairingEventRow,
            ProcessKillEventRow, BtFrameworkEventRow))
        stored = [focus.detail, tomb.cmdline, anr.subject, anr.reason,
                  cdm.detail, kill.reason, bt.detail]
        for text in stored:
            assert "jdoe@example.com" not in text and "4155550123" not in text, text
            assert EMAIL_TOKEN in text and PHONE_TOKEN in text, text
        assert mac in cdm.detail and mac in bt.detail
        assert cdm.mac_address == mac and bt.address == mac
        assert tomb.fault_addr == "0x0000007b2c4d1e80"
        assert tomb.build_fingerprint.endswith("10754064:user/release-keys")
        assert anr.package == kill.package == "com.example.app"
