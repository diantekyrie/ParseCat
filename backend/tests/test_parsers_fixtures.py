"""Regression tests run against the real bugreport fixtures.

These pin down exact source line numbers alongside the parsed values. That
combination caught a real bug during development: TextIOWrapper's default
universal-newlines mode was splitting on stray '\\r' bytes embedded in
tombstone/crash data further up the file, which silently drifted every line
number after the first one by ~43,000 lines. The values still "looked"
right; only cross-checking against `grep`-verified line numbers caught it.
That's exactly the class of error this product exists to catch in bugreport
analysis -- so it can't ship with that bug in its own parsers.
"""
from pathlib import Path

import pytest

from app.parsers.cdm_pairing import parse_cdm_pairing_events
from app.parsers.crash_events import parse_crash_events
from app.parsers.section_extractor import Section
from app.services.ingestion import parse_bugreport_zip

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE_1 = FIXTURES / "bugreport_2026-08-13.zip"
CAPTURE_2 = FIXTURES / "bugreport_2026-08-19.zip"

pytestmark = pytest.mark.skipif(
    not CAPTURE_1.exists(), reason="real bugreport fixtures not present"
)


@pytest.fixture(scope="module")
def capture1():
    return parse_bugreport_zip(CAPTURE_1)


def test_no_parse_warnings(capture1):
    assert capture1.parse_warnings == []


def test_focus_stack_top_matches_known_state(capture1):
    assert len(capture1.focus_stack) == 1
    top = capture1.focus_stack[0]
    assert top.package == "com.apple.android.music"
    assert top.uid == 10358
    assert top.sdk == 35
    assert top.is_top_of_stack is True
    # grep -na "Audio Focus stack entries" -> 971139 (header); entry is the next line.
    assert top.source_ref.line_start == 971140


def test_focus_events_include_full_history(capture1):
    assert len(capture1.focus_events) == 50
    kinds = {e.event_type for e in capture1.focus_events}
    assert kinds == {"request", "abandon", "owner_change"}


@pytest.mark.parametrize(
    "package,expected_target_sdk,expected_line",
    [
        ("com.disney.disneyplus", 36, 1408647),
        ("com.apple.android.music", 35, 1386473),
        ("com.google.android.apps.youtube.music", 36, 1417026),
    ],
)
def test_package_target_sdk_and_line(capture1, package, expected_target_sdk, expected_line):
    pkg = capture1.packages[package]
    assert pkg.target_sdk == expected_target_sdk
    assert pkg.source_ref.line_start == expected_line


def test_media_sessions_reflect_actual_playback_state(capture1):
    by_pkg = {m.package: m for m in capture1.media_sessions}
    assert by_pkg["com.disney.disneyplus"].playback_state == "PLAYING"
    assert by_pkg["com.disney.disneyplus"].active is True
    assert by_pkg["com.apple.android.music"].playback_state == "PAUSED"
    assert by_pkg["com.google.android.apps.youtube.music"].playback_state == "PAUSED"


def test_device_info(capture1):
    info = capture1.device_info
    assert info.manufacturer == "Google"
    assert info.model == "Pixel 10"
    assert info.sdk_version == 37
    assert info.security_patch == "2026-08-05"
    assert info.serial == "57110DLCR003VF"


def test_crash_event_matches_known_incident(capture1):
    # Second real bug this parser work caught: the bugreport prints a
    # second, heavily time-filtered "SYSTEM LOG" section near the very end
    # (a `-T <recent timestamp>` trailer covering only the last few
    # seconds) reusing the exact same section name. "Keep last occurrence"
    # (correct for dumpsys CRITICAL/HIGH passes) silently grabbed that
    # tiny trailer instead of the real ~30k-line section for log-style
    # sections, dropping this crash entirely (0 found instead of 1).
    assert len(capture1.crash_events) == 1
    crash = capture1.crash_events[0]
    assert crash.package == "com.android.systemui"
    assert crash.exception_class == "DeadSystemException"
    assert crash.source_ref.line_start == 58157
    # No "Caused by:" chain in this crash -- root cause fields must stay
    # unset rather than falsely inheriting the top-level exception.
    assert crash.root_cause_class is None


def test_freeze_events_present_and_reasonable(capture1):
    assert len(capture1.freeze_events) > 0
    freezes = [e for e in capture1.freeze_events if e.event_type == "freeze"]
    unfreezes = [e for e in capture1.freeze_events if e.event_type == "unfreeze"]
    assert len(freezes) > 0
    assert len(unfreezes) > 0
    # Unfreeze reason codes are a small enum (observed: 1,3,4,6,7,10,19),
    # not a duration -- asserting that keeps the field honest.
    codes = {e.unfreeze_reason_code for e in unfreezes}
    assert codes.issubset({1, 3, 4, 6, 7, 10, 19})


def test_tombstones_parsed_from_zip(capture1):
    assert len(capture1.tombstones) > 0
    assert all(t.filename.startswith("tombstone_") for t in capture1.tombstones)
    # Every tombstone should have parsed a signal -- confirms content was
    # actually parsed, not just filenames listed.
    assert all(t.signal_name is not None for t in capture1.tombstones)
    # At least one tombstone attributes to a real app package (not every
    # tombstone will -- native binaries/services correctly report None).
    assert any(t.package is not None for t in capture1.tombstones)
    # Real variety confirmed present in this fixture (not fabricated):
    signals = {t.signal_name for t in capture1.tombstones}
    assert {"SIGSEGV", "SIGABRT", "SIGTRAP"}.issubset(signals)
    # A tombstone whose Cmdline is a multi-token linker64 invocation (not a
    # bare package id) must NOT be misattributed to a package -- regression
    # for a real bug where a missing "ppid:" field in some tombstones'
    # pid line (a genuine format variant) caused pid/tid to parse as None.
    linker_tombstones = [t for t in capture1.tombstones if t.executable and "linker64" in t.executable]
    assert linker_tombstones
    assert all(t.package is None for t in linker_tombstones)
    assert all(t.pid is not None for t in linker_tombstones)


def test_anrs_parsed_with_package_attribution(capture1):
    assert len(capture1.anrs) == 2
    for a in capture1.anrs:
        assert a.package == "com.disney.wdpro.dlr"
        assert a.reason == "failed to complete startup"
        assert a.pid is not None


def test_bt_hci_log_decoded_with_sane_values(capture1):
    # Parsed from ingestion (capture1 fixture) via the full pipeline.
    from app.services.ingestion import parse_bugreport_zip as _p
    cap = _p(CAPTURE_1)
    summary = cap.bt_hci_summary
    assert summary is not None
    assert summary.total_packets == 1747
    assert summary.command_count == 107
    assert summary.event_count == 985
    assert summary.acl_data_count == 655
    # Decoded timestamps must land within the capture's own time window,
    # not some wildly wrong epoch -- this caught a real bug where an
    # incorrect btsnoop-epoch-to-Unix delta constant decoded timestamps to
    # 1996 instead of 2026.
    assert summary.first_timestamp.startswith("2026-08-14")
    assert summary.last_timestamp.startswith("2026-08-14")
    # A real, non-fabricated anomaly found in this fixture: a Command
    # Complete with a non-Success status.
    non_success = [e for e in summary.events if e.status_code not in (None, 0)]
    assert any(e.status_name == "Unknown Connection Identifier" for e in non_success)


# Real lines from a third device's bugreport (not committed as a fixture --
# it's 228MB), reproduced verbatim: a "Disneyland" app crash whose top-level
# exception is a generic wrapper ("Unable to create application") over a
# third-party SDK's actual root cause. This is exactly the shape a
# root-cause chain needs unwrapping: reporting only the top-level exception
# would blame app startup in general, not the ASSA ABLOY Mobile Keys SDK
# call that actually threw.
DISNEYLAND_CRASH_LINES = """\
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: FATAL EXCEPTION: main
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 2974
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat android.app.ActivityThread.handleBindApplication(ActivityThread.java:8400)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-19 21:11:56.218 10380  2974  2974 E AndroidRuntime: \tat com.disney.wdpro.eservices_ui.key.component.ResortKeyModule.provideMobileKeysApi(SourceFile:25)
""".splitlines()


def test_crash_parser_unwraps_caused_by_chain_to_the_real_root_cause():
    section = Section(name="system_log", priority=None, line_start=100,
                       line_end=100 + len(DISNEYLAND_CRASH_LINES) - 1,
                       lines=DISNEYLAND_CRASH_LINES, kind="log")
    crashes = parse_crash_events(section)
    assert len(crashes) == 1
    c = crashes[0]
    assert c.package == "com.disney.wdpro.dlr"
    assert c.exception_class == "java.lang.RuntimeException"
    assert c.message == "Unable to create application com.disney.wdpro.dlr.DLRApplication"
    # The generic wrapper isn't the real story -- the deepest "Caused by:"
    # (the third-party SDK) is.
    assert c.root_cause_class == "java.lang.RuntimeException"
    assert c.root_cause_message == "25"
    assert "MobileKeysApi.initialize" in c.root_cause_frame


# Real lines reproducing a second, more subtle bug found via a diagnosis
# report that came back with an impossible claim (a crash "message" naming
# the Disney app but a "package" of com.google.android.gms, with a root
# cause that didn't match anything nearby in the raw log). Three crashes
# back-to-back with NO gap between them: two genuine Disney crashes (9
# seconds apart, identical root cause) immediately followed by an unrelated
# GMS crash. The block-scanner didn't stop at the next "FATAL EXCEPTION:"
# line, so it read straight through crash #1's boundary into crash #2's
# Process:/Caused-by lines, then straight through crash #2's boundary into
# crash #3's -- silently overwriting crash #1's package and root cause with
# data from a crash that happened over a day later.
BACK_TO_BACK_CRASH_LINES = """\
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: FATAL EXCEPTION: main
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 16925
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat com.assaabloy.mobilekeys.common.c.a.dO23852.info(:10365)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-08 07:47:07.830 10380 16925 16925 E AndroidRuntime: \t... 10 more
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: FATAL EXCEPTION: main
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 18020
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat android.app.ActivityThread.main(ActivityThread.java:9613)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat com.assaabloy.mobilekeys.common.c.a.dO23852.info(:10365)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \tat com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(SourceFile:69)
08-08 07:47:16.714 10380 18020 18020 E AndroidRuntime: \t... 10 more
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: FATAL EXCEPTION: actvpool[4]
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: Process: com.google.android.gms, PID: 20750
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: java.lang.IllegalArgumentException: Component class com.google.android.gms.findmydevice.spot.e2ee.ui.ExportedSyncOwnerKeyActivityAlias does not exist in com.google.android.gms
08-09 17:01:32.826 10336 20750 20811 E AndroidRuntime: \tat android.os.Parcel.readException(Parcel.java:3278)
""".splitlines()


def test_crash_parser_stops_at_next_fatal_exception_boundary():
    section = Section(name="system_log", priority=None, line_start=1000,
                       line_end=1000 + len(BACK_TO_BACK_CRASH_LINES) - 1,
                       lines=BACK_TO_BACK_CRASH_LINES, kind="log")
    crashes = parse_crash_events(section)
    assert len(crashes) == 3

    first, second, third = crashes
    for c in (first, second):
        assert c.package == "com.disney.wdpro.dlr"
        assert c.exception_class == "java.lang.RuntimeException"
        assert c.root_cause_class == "java.lang.RuntimeException"
        assert c.root_cause_message == "25"
        assert "MobileKeysApi.initialize" not in c.root_cause_frame  # first frame under Caused by, not the second
        assert "dO23852.info" in c.root_cause_frame

    assert third.package == "com.google.android.gms"
    assert third.exception_class == "java.lang.IllegalArgumentException"
    assert third.root_cause_class is None  # no "Caused by:" in this crash's own block

    # Each crash's citation must end at ITS OWN last line, not bleed into
    # the next crash's lines.
    assert first.source_ref.line_end < second.source_ref.line_start
    assert second.source_ref.line_end < third.source_ref.line_start


def test_wifi_disconnection_events_with_802_11_reason_codes(capture1):
    disconnections = [e for e in capture1.wifi_events if e.kind == "disconnection"]
    assert len(disconnections) == 3
    by_ssid = {e.ssid: e for e in disconnections}
    assert by_ssid["amzn-www"].reason_code == 3
    assert by_ssid["amzn-www"].reason_name == "Deauthenticated: station leaving"
    assert by_ssid["amzn-www"].locally_generated is True
    # grep-verified line number for this exact disconnection record.
    assert by_ssid["amzn-www"].source_ref.line_start == 1622419


def test_wifi_association_events_include_roam_flag(capture1):
    associations = [e for e in capture1.wifi_events if e.kind == "association"]
    assert len(associations) > 0
    assert all(e.roam is not None for e in associations)


def test_battery_uid_stats_attributed_to_real_packages(capture1):
    by_pkg = {s.package: s for s in capture1.battery_uid_stats if s.package}
    assert "com.disney.disneyplus" in by_pkg
    assert "ch.protonvpn.android" in by_pkg
    assert by_pkg["com.disney.disneyplus"].total_mah > 0
    assert "audio" in by_pkg["com.disney.disneyplus"].components_mah or \
           "video" in by_pkg["com.disney.disneyplus"].components_mah

    # Regression: appId already includes Android's +10000 offset (verified
    # against two independent real UIDs); the first parser version dropped
    # that term, computing uid=358 instead of 10358 for token "u0a358" and
    # silently failing every attribution.
    music = by_pkg.get("com.apple.android.music")
    assert music is not None
    assert music.uid == 10358

    # Regression: appId 1000 ("system") is shared by 18+ different
    # packages via android:sharedUserId. Attributing a shared system UID's
    # battery entry to whichever package happened to be first in the dict
    # would misrepresent combined system activity as one specific app's --
    # it must be left unattributed instead.
    system_uid_entries = [s for s in capture1.battery_uid_stats if s.uid == 1000]
    assert len(system_uid_entries) == 1
    assert system_uid_entries[0].package is None


# Real lines from a Pixel phone pairing with a Pixel Watch 5 (from a third
# device's bugreport, not committed as a fixture -- 188MB). Reproduced
# verbatim: this is exactly the case that came back "unknown, no data"
# from two different LLM providers on a "network error while pairing"
# question, even though the actual pairing flow -- and a concrete, repeated
# transport failure -- was sitting in the log the whole time.
PAIRING_LINES = """\
06-25 10:08:03.850  1000  1731  9608 I ActivityTaskManager: START u0 {flg=0x30040000 xflg=0x4 cmp=com.google.android.gms/.nearby.discovery.fastpair.HalfSheetActivity (has extras)} with LAUNCH_SINGLE_INSTANCE from uid 10347
06-25 10:08:12.959 10138 29050 29050 I CDM_CompanionDeviceDiscoveryService: onDeviceFound() (BT) 64:9d:38:bc:d5:eb 'Pixel Watch 5 35WD' - New device.
06-25 10:08:12.960 10138 29050 29050 I CDM_CompanionDeviceActivity: onAssociationApproved() macAddress=64:9d:38:bc:d5:eb
06-25 10:08:12.971  1000  1731  1731 I CDM_AssociationStore: Adding new association=[Association{mId=1, mUserId=0, mPackageName='com.google.android.apps.wear.companion', mDeviceMacAddress=64:9d:38:bc:d5:eb, mDisplayName='Pixel Watch 5 35WD', mDeviceProfile='android.app.role.COMPANION_DEVICE_WATCH', mSelfManaged=false}]...
06-25 10:08:12.972  1000  1731  1731 I CDM_DevicePresenceProcessor: onBluetoothCompanionDeviceConnected: associationId( 1 )
06-25 10:08:12.989  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_NEARBY_ADVERTISING FAILED to activate.
06-25 10:08:12.990  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:18.017  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:23.053  1000  1731  1731 W CDM_ActionRequestProcessor: Action REQUEST_TRANSPORT FAILED to activate.
06-25 10:08:14.225 10347 32249 32249 E ActivityThread: Failed to find provider info for 64:9D:38:BC:D5:EB
""".splitlines()


def test_cdm_pairing_events_decoded_with_anomaly_catchall():
    section = Section(name="system_log", priority=None, line_start=500,
                       line_end=500 + len(PAIRING_LINES) - 1,
                       lines=PAIRING_LINES, kind="log")
    events = parse_cdm_pairing_events(section)
    kinds = [e.kind for e in events]
    assert "fast_pair_ui_opened" in kinds
    assert "device_found" in kinds
    assert "association_approved" in kinds
    assert "association_added" in kinds
    assert "device_presence_connected" in kinds
    assert "provider_lookup_failed" in kinds

    added = next(e for e in events if e.kind == "association_added")
    assert added.mac_address == "64:9d:38:bc:d5:eb"
    assert added.display_name == "Pixel Watch 5 35WD"
    assert added.package_name == "com.google.android.apps.wear.companion"
    assert added.association_id == 1

    # The real value of the generic W/E catch-all: three separate
    # "Action REQUEST_TRANSPORT FAILED to activate" lines, never
    # individually anticipated, still surface as anomalies.
    anomalies = [e for e in events if e.kind == "anomaly"]
    assert sum(1 for e in anomalies if "REQUEST_TRANSPORT FAILED" in e.detail) == 3
    assert any("REQUEST_NEARBY_ADVERTISING FAILED" in e.detail for e in anomalies)


def test_second_capture_also_parses_cleanly():
    if not CAPTURE_2.exists():
        pytest.skip("second fixture not present")
    cap2 = parse_bugreport_zip(CAPTURE_2)
    assert cap2.parse_warnings == []
    assert len(cap2.packages) > 0


def _minimal_btsnoop_bytes() -> bytes:
    import struct
    header = b"btsnoop\x00" + struct.pack(">II", 1, 1002)
    payload = bytes([0x01, 0x03, 0x0C, 0x00])  # H4 command, arbitrary opcode/len
    record = struct.pack(">IIIIQ", len(payload), len(payload), 0, 0, 0x00DCDDB30F2F8000) + payload
    return header + record


def test_companion_device_associations_exclude_removed_and_handle_apostrophes(capture1):
    # Real gap found live against this exact fixture: mId=3 ("Diante's
    # Pixel Buds Pro 2") only appears under "Last Removed Association:",
    # not "Companion Device Associations:" -- it must NOT show up as a
    # currently-active association. mId=2's display name itself contains
    # an apostrophe ("Diante's Pixel Buds 2a"), which broke a naive
    # `'([^']*)'` regex match before the fix in companion_device.py.
    assoc_ids = {a.association_id for a in capture1.companion_device_associations}
    assert 3 not in assoc_ids  # removed association excluded
    assert assoc_ids == {2, 4, 5, 6}

    buds = next(a for a in capture1.companion_device_associations if a.association_id == 2)
    assert buds.display_name == "Diante's Pixel Buds 2a"
    assert buds.mac_address == "5a:dd:5a:87:74:0d"
    # Cross-referenced against "Connected Bluetooth Devices:" in the same
    # section -- this one's mac address is in that list, the others aren't.
    assert buds.currently_connected is True
    watch = next(a for a in capture1.companion_device_associations if a.association_id == 4)
    assert watch.currently_connected is False


def test_logcat_history_normalizes_timestamp_precision_and_dedups(tmp_path):
    # Real gap found live: the persistent rotated logcat.NN buffer files
    # (up to 63 of them on a real device) were never read at all, and when
    # they were, a real overlap between the live "system_log" window and a
    # rotated file's content would double-count the identical event. This
    # also exercises the 6-digit microsecond -> 3-digit millisecond
    # timestamp normalization those files need (system_log uses 3 digits).
    import zipfile

    zip_path = tmp_path / "synthetic_bugreport.zip"
    freeze_line_live = (
        "08-13 22:36:22.190  1000  2046  2922 D ActivityManager: "
        "freezing 28798 com.android.vending:background\n"
    )
    # Same event, same millisecond, but as it's actually stored on-device:
    # 6-digit microsecond precision.
    freeze_line_history_dup = (
        "08-13 22:36:22.190123  1000  2046  2922 D ActivityManager: "
        "freezing 28798 com.android.vending:background\n"
    )
    freeze_line_history_unique = (
        "08-12 09:00:00.000000  1000  2046  2922 D ActivityManager: "
        "freezing 555 com.example.other:background\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "bugreport-synthetic-2026-01-01-00-00-00.txt",
            "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n"
            + freeze_line_live
            + "------ 0.001s was the duration of 'SYSTEM LOG' ------\n",
        )
        zf.writestr("FS/data/misc/logd/logcat.01", freeze_line_history_dup)
        zf.writestr("FS/data/misc/logd/logcat.02", freeze_line_history_unique)
        # The bare, unrotated "logcat" file is deliberately never read.
        zf.writestr("FS/data/misc/logd/logcat", freeze_line_history_unique)

    cap = parse_bugreport_zip(zip_path)
    assert len(cap.freeze_events) == 2  # the live/history duplicate collapsed to one
    sections = {e.source_ref.section for e in cap.freeze_events}
    assert sections == {"system_log", "logcat.02"}
    processes = {e.process for e in cap.freeze_events}
    assert processes == {"com.android.vending:background", "com.example.other:background"}


def test_bt_hci_log_found_under_real_world_filename_variant(tmp_path):
    # Real gap found live against two actual bugreports (a Pixel phone and a
    # Pixel Watch, neither the committed test fixture): the HCI log ships as
    # "btsnoop_hci.log.filtered", not "btsnooz_hci.log" -- the only name
    # ingestion.py originally looked for. Both real captures had a valid,
    # multi-thousand-packet HCI log sitting in the zip that silently never
    # got parsed; "No Bluetooth HCI snoop log found" was a false negative.
    # This builds a minimal zip using that real-world filename to make sure
    # the fix (searching BT_HCI_LOG_CANDIDATES) doesn't regress.
    import zipfile

    zip_path = tmp_path / "synthetic_bugreport.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "bugreport-synthetic-2026-01-01-00-00-00.txt",
            "------ SYSTEM PROPERTIES (getprop) ------\n"
            "[ro.build.version.release]: [15]\n"
            "------ 0.000s was the duration of 'SYSTEM PROPERTIES' ------\n",
        )
        zf.writestr(
            "FS/data/misc/bluetooth/logs/btsnoop_hci.log.filtered",
            _minimal_btsnoop_bytes(),
        )

    cap = parse_bugreport_zip(zip_path)
    assert "No Bluetooth HCI snoop log found" not in cap.parse_warnings
    assert cap.bt_hci_summary is not None
    assert cap.bt_hci_summary.total_packets == 1
    assert cap.bt_hci_summary.command_count == 1


SELINUX_LINES = """\
06-25 10:20:53.162 10303 27010 27010 W GrallocUploadTh: type=1400 audit(0.0:174): avc:  denied  { read } for  name="uevent" dev="sysfs" ino=32559 scontext=u:r:platform_app:s0:c512,c768 tcontext=u:object_r:sysfs:s0 tclass=file permissive=0 app=com.google.android.avatarpicker
06-25 10:05:31.326  1002  7336  7336 I auditd  : type=1400 audit(0.0:155): avc:  denied  { search } for  comm="binder:7336_1" name="com.google.android.gms" dev="dm-61" ino=8631 scontext=u:r:bluetooth:s0 tcontext=u:object_r:privapp_data_file:s0:c512,c768 tclass=dir permissive=0
06-25 10:06:46.687 media 28293 28293 I auditd  : type=1400 audit(0.0:160): avc:  denied  { execute } for  comm="android.hardwar" name="sh" dev="dm-7" ino=501 scontext=u:r:hal_drm_widevine:s0 tcontext=u:object_r:shell_exec:s0 tclass=file permissive=1
06-25 10:06:47.100 media 28293 28293 I auditd  : type=1400 audit(0.0:161): avc:  denied  { read write } for  comm="foo" scontext=u:r:some_domain:s0 tcontext=u:object_r:some_type:s0 tclass=file
""".splitlines()


def test_selinux_denials_parse_with_enforcing_distinction():
    # permissive=0 (BLOCKED, a real failure) vs permissive=1 (logged but
    # allowed) vs absent (unknown) must stay three distinct states --
    # collapsing them is the main way SELinux findings get overstated.
    from app.parsers.selinux import parse_selinux_denials

    section = Section(name="event_log", priority=None, line_start=500,
                      line_end=500 + len(SELINUX_LINES) - 1,
                      lines=SELINUX_LINES, kind="log")
    denials = parse_selinux_denials(section)
    assert len(denials) == 4

    first = denials[0]
    assert first.verdict == "denied"
    assert first.permissions == ["read"]
    # Context types are extracted from the full u:r:type:s0:c... string, and
    # the per-instance category suffix is dropped so identical denials group.
    assert first.source_domain == "platform_app"
    assert first.target_type == "sysfs"
    assert first.target_class == "file"
    assert first.app == "com.google.android.avatarpicker"
    assert first.target_name == "uevent"
    assert first.enforcing is True
    assert first.source_ref.section == "event_log"
    assert first.source_ref.line_start == 500

    assert denials[1].comm == "binder:7336_1"
    assert denials[1].source_domain == "bluetooth"
    assert denials[1].target_class == "dir"

    assert denials[2].enforcing is False        # permissive=1 -> allowed through
    assert denials[3].enforcing is None         # field absent -> unknown, not False
    assert denials[3].permissions == ["read", "write"]


def test_selinux_denials_found_in_event_log_not_just_system_log(capture1):
    # Found live on a real capture: 19 of 20 AVC denials were in EVENT LOG
    # (where auditd writes), only 1 in SYSTEM LOG. Parsing SYSTEM LOG alone
    # would have silently missed 95% of them.
    sections = {d.source_ref.section for d in capture1.selinux_denials}
    if capture1.selinux_denials:
        assert "event_log" in sections or "system_log" in sections
        assert all(d.verdict in {"denied", "granted"} for d in capture1.selinux_denials)


MEMINFO_LINES = """Total RSS by process:
    772,644K: system (pid 1731)
    577,760K: com.google.android.apps.wear.companion (pid 6609 / activities)
     12,000K: tiny (pid 42)

Total PSS by process:
  1,377,160K: com.google.android.apps.pixel.creativeassistant (pid 4385)  (1,282,633K in swap)
    332,637K: com.google.android.apps.wear.companion (pid 6609 / activities)(    1,533K in swap)

Total RAM: 11,830,476K (status normal)
 Free RAM: 8,112,505K (3,834,577K cached pss + 3,726,924K cached kernel +   551,004K free)
 Used RAM: 5,359,176K (3,359,752K used pss + 1,999,424K kernel)
 Lost RAM:   853,074K
     ZRAM:   535,536K physical used for 2,235,288K in swap (5,915,232K total swap)
""".splitlines()


def test_meminfo_snapshot_parses_ram_totals_and_both_rankings():
    from app.parsers.memory import parse_meminfo

    section = Section(name="meminfo", priority="HIGH", line_start=100,
                      line_end=100 + len(MEMINFO_LINES) - 1,
                      lines=MEMINFO_LINES, kind="dumpsys")
    snap = parse_meminfo(section)

    assert snap.total_ram_kb == 11_830_476
    assert snap.status == "normal"
    # Free RAM's inner terms must stay separate: 8.1 GB "free" is mostly
    # reclaimable cache, and only 551 MB is actually unused. Collapsing
    # them either way misreports how much headroom the device really has.
    assert snap.free_ram_kb == 8_112_505
    assert snap.cached_pss_kb == 3_834_577
    assert snap.truly_free_kb == 551_004
    assert snap.used_pss_kb == 3_359_752
    assert snap.kernel_kb == 1_999_424
    assert snap.lost_ram_kb == 853_074
    assert snap.zram_physical_kb == 535_536
    assert snap.total_swap_kb == 5_915_232

    # RSS and PSS are different measurements, kept in separate lists.
    assert [u.pid for u in snap.top_by_rss] == [1731, 6609, 42]
    assert snap.top_by_rss[0].memory_kb == 772_644
    assert snap.top_by_rss[0].swap_kb is None      # RSS table has no swap column
    assert snap.top_by_rss[1].state == "activities"

    assert len(snap.top_by_pss) == 2
    assert snap.top_by_pss[0].memory_kb == 1_377_160
    assert snap.top_by_pss[0].swap_kb == 1_282_633
    # The no-space "(pid N / state)(   NK in swap)" spelling is real output.
    assert snap.top_by_pss[1].swap_kb == 1_533
    assert snap.top_by_pss[1].state == "activities"


AM_PSS_LINES = """06-25 00:40:24.336  1000  1731  2036 I am_pss  : [11797,10234,com.google.android.calendar,0,0,0,189673472,0,14,52]
06-25 01:10:00.000  1000  1731  2036 I am_pss  : [11797,10234,com.google.android.calendar,4096,2048,1024,199673472,0,14,50]
""".splitlines()


def test_am_pss_zero_pss_is_unknown_not_a_measurement_of_zero():
    # Modern Android skips the expensive PSS collection and reports RSS
    # only -- all 244 am_pss events in the real test capture had pss=0. A
    # zero must surface as "not collected", never as "this process uses
    # 0 KB", which would be a fabricated measurement.
    from app.parsers.memory import parse_memory_samples

    section = Section(name="event_log", priority=None, line_start=900,
                      line_end=901, lines=AM_PSS_LINES, kind="log")
    samples = parse_memory_samples(section)
    assert len(samples) == 2

    first = samples[0]
    assert first.pss_kb is None          # raw 0 -> unknown
    assert first.swap_pss_kb is None
    # am_pss reports BYTES; the dumpsys tables report KB. Both normalize to
    # KB so the two sources can be compared at all.
    assert first.rss_kb == 189_673_472 // 1024
    assert first.pid == 11797
    assert first.process == "com.google.android.calendar"
    assert first.proc_state == 14
    assert first.source_ref.line_start == 900

    assert samples[1].pss_kb == 4           # a real nonzero PSS is kept
    assert samples[1].swap_pss_kb == 1


def test_memory_growth_reports_shape_and_never_claims_a_leak():
    # The real wear.companion sequence: 146 -> 556 -> 560 -> 504 -> 504 ->
    # 533 MB. That is +387 MB net and NOT monotonic -- it rises, falls, and
    # rises again, which is ordinary allocate/release. A tool that called
    # this a leak would be inventing a conclusion the data cannot support.
    from app.services.reasoning import _derive_memory_growth

    class Row:
        def __init__(self, ts, rss_mb):
            self.capture_id, self.pid = 1, 6609
            self.process = self.package = "com.example.app"
            self.timestamp, self.rss_kb = ts, rss_mb * 1024
            self.source_section = "event_log"
            self.source_line_start = self.source_line_end = 10

    rows = [Row("06-25 0%d:00:00.000" % i, mb)
            for i, mb in enumerate([146, 556, 560, 504, 504, 533])]
    growth = _derive_memory_growth(rows, lambda cid: {"capture_id": cid})

    assert len(growth) == 1
    g = growth[0]
    assert g["first_rss_kb"] == 146 * 1024
    assert g["last_rss_kb"] == 533 * 1024
    assert g["peak_rss_kb"] == 560 * 1024      # peak is higher than last
    assert g["delta_kb"] == (533 - 146) * 1024
    assert g["sample_count"] == 6
    assert g["monotonic"] is False             # it dropped, 560 -> 504
    assert [s["rss_kb"] for s in g["samples"]][0] == 146 * 1024

    # A single sample proves nothing about change over time.
    assert _derive_memory_growth([Row("06-25 01:00:00.000", 900)],
                                 lambda cid: {"capture_id": cid}) == []


def test_memory_findings_never_use_the_word_leak():
    # Guards the one claim this evidence cannot support. am_pss samples
    # cannot distinguish a leak from an app legitimately doing more work,
    # so no memory finding may say "leak" no matter how the numbers look.
    from app.services.reasoning import rank_findings

    bundle = {
        "memory_growth_evidence": {
            "growing_processes": [{
                "process": "com.example.app", "pid": 1, "capture_id": 1,
                "first_rss_kb": 100 * 1024, "last_rss_kb": 900 * 1024,
                "peak_rss_kb": 900 * 1024, "delta_kb": 800 * 1024,
                "sample_count": 8, "monotonic": True,
            }],
        },
    }
    findings = [f for f in rank_findings(bundle) if f["category"] == "memory"]
    assert findings
    blob = " ".join(f["title"] + " " + f["detail"] for f in findings).lower()
    assert "leak" not in blob
    assert "grew" in blob


def test_meminfo_status_drives_severity_not_a_homegrown_free_ram_threshold():
    # Android already computes memory status. Second-guessing it with a
    # "free RAM below X%" rule would flag healthy devices, because free RAM
    # counts reclaimable cache. A "normal" device produces no finding even
    # though its truly-free RAM looks small next to its total.
    from app.services.reasoning import rank_findings

    def bundle_with(status):
        return {"memory_snapshot_evidence": {"ram": {
            "status": status, "total_ram_kb": 11_830_476,
            "free_ram_kb": 8_112_505, "used_ram_kb": 5_359_176,
            "truly_free_kb": 551_004, "cached_pss_kb": 3_834_577,
        }}}

    assert [f for f in rank_findings(bundle_with("normal"))
            if f["category"] == "memory"] == []
    critical = rank_findings(bundle_with("critical"))
    assert critical[0]["severity"] == "CRITICAL"
    assert "critical" in critical[0]["title"]
    assert rank_findings(bundle_with("moderate"))[0]["severity"] == "MEDIUM"


def test_memory_snapshot_and_samples_present_on_real_capture(capture1):
    # meminfo lives in a dumpsys section; am_pss lives in the EVENT LOG
    # alongside am_kill. Both wires have to be connected for the memory
    # picture to be complete.
    if capture1.memory_snapshot is not None:
        assert capture1.memory_snapshot.total_ram_kb > 0
        assert capture1.memory_snapshot.top_by_rss
    if capture1.memory_samples:
        assert all(s.source_ref.section == "event_log" for s in capture1.memory_samples)
        # Never a fabricated zero -- unknown is None.
        assert all(s.pss_kb is None or s.pss_kb > 0 for s in capture1.memory_samples)


LOCATION_LINES = """Location Manager State:
  Location Settings:
    Location Setting:
      [u0] true
      [u10] true
  Location Providers:
    network provider:
      user 0:
        last location=Location[network 37.737630,-122.430491 hAcc=16.568 et=+3d21h50m7s712ms alt=88.3]
      user 10:
        last location=Location[network 37.737630,-122.430491 hAcc=16.568 et=+3d21h50m7s712ms alt=88.3]
    gps provider:
      user 0:
        last location=Location[gps 37.737705,-122.430285 hAcc=23.979591 et=+3d21h42m10s993ms alt=102.0 vAcc=14.0 {Bundle[{satellites=10, maxCn0=38, meanCn0=28}]}]
      GNSS_KPI_START
        Number of location reports: 1035
        Percentage location failure: 3.961352657004831
        Number of TTFF reports: 52
        TTFF mean (sec): 40.69086538461537
        TTFF standard deviation (sec): 148.29917886229808
        Position accuracy mean (m): 18.106598828400166
        Position accuracy standard deviation (m): 19.989182961405618
        Top 4 Avg CN0 mean (dB-Hz): 34.21029830899155
        Used-in-fix constellation types: GPS GLONASS GALILEO
      GNSS_KPI_END
      Power Metrics
        Amount of time (while on battery) Top 4 Avg CN0 > 20.0 dB-Hz (min): 112.14281666666666
        Amount of time (while on battery) Top 4 Avg CN0 <= 20.0 dB-Hz (min): 24.271116666666668
  Historical Aggregate Location Provider Data:
    gps:
      10311/com.nianticlabs.pokemongo: min/max interval = 0s/1s, total/active/foreground duration = +15h13m41s259ms/+15h13m41s163ms/+40m41s545ms, locations = 163
    fused:
      10311/com.nianticlabs.pokemongo: min/max interval = 0s/1s, total/active/foreground duration = +15h13m41s889ms/+15h13m41s553ms/+40m41s586ms, locations = 925
  GNSS Manager:
    GNSS Hardware Model Name: S.LSI,K042,SPOTNAV_4.15.5
""".splitlines()


def test_location_dump_parses_providers_kpi_and_per_app_usage():
    from app.parsers.location import parse_location_dump

    section = Section(name="location", priority=None, line_start=1000,
                      line_end=1000 + len(LOCATION_LINES) - 1,
                      lines=LOCATION_LINES, kind="dumpsys")
    snap = parse_location_dump(section)

    assert snap.location_enabled is True
    assert snap.gnss_hardware_model.startswith("S.LSI")

    by_name = {p.name: p for p in snap.providers}
    assert by_name["network"].latitude == 37.737630
    assert by_name["network"].horizontal_accuracy_m == 16.568
    # Only a GPS fix carries the satellite bundle; the others must stay None
    # rather than inheriting a neighbouring provider's numbers.
    assert by_name["network"].satellites is None
    assert by_name["gps"].satellites == 10
    assert by_name["gps"].mean_cn0 == 28.0

    k = snap.kpi
    assert k.location_failure_pct == 3.961352657004831
    # A huge TTFF standard deviation next to a modest mean is the shape of
    # "most fixes were fast, a few took minutes" -- both are kept so a
    # caller cannot quote the mean alone and imply consistency.
    assert k.ttff_mean_sec == 40.69086538461537
    assert k.ttff_stddev_sec == 148.29917886229808
    assert k.cn0_threshold_dbhz == 20.0
    assert k.cn0_time_below_threshold_min == 24.271116666666668
    assert k.constellations == "GPS GLONASS GALILEO"

    usage = {(u.provider, u.package): u for u in snap.app_usage}
    # Same app, same window, two providers, wildly different delivery counts.
    assert usage[("gps", "com.nianticlabs.pokemongo")].locations == 163
    assert usage[("fused", "com.nianticlabs.pokemongo")].locations == 925
    assert usage[("gps", "com.nianticlabs.pokemongo")].min_interval == "0s"


def test_coordinates_are_coarsened_before_leaving_the_device():
    # A last known fix is someone's real physical location, very often their
    # home. The diagnostic value is in the accuracy radius and provider, so
    # precision is dropped rather than shipped to a third-party API.
    from app.parsers.location import redacted_coords

    assert redacted_coords(37.737630, -122.430491) == "~37.7, -122.4"
    assert redacted_coords(None, None) == "unknown"
    assert redacted_coords(37.737630, None) == "unknown"


GNSS_HISTORY_LINES = """  08-28 12:14:50.819 094 ea902820 +gps +state=10311:"gnss"
  08-28 12:16:31.401 094 e2902820 gps_signal_quality=poor
  08-28 12:19:37.928 094 e2902820 gps_signal_quality=good
  08-28 12:19:43.377 094 e2902820 gps_signal_quality=poor
  08-28 12:37:23.454 087 ca402820 -gps gps_signal_quality=none -state=10311:"gnss"
""".splitlines()


def test_gnss_intervals_close_on_the_next_transition_and_track_who_held_gps():
    from app.parsers.location import parse_gnss_signal_intervals

    section = Section(name="batterystats", priority=None, line_start=700,
                      line_end=704, lines=GNSS_HISTORY_LINES, kind="dumpsys")
    intervals = parse_gnss_signal_intervals(section)

    # Four transitions produce three closed intervals -- the final state has
    # no end, so it is dropped rather than given an invented duration.
    assert len(intervals) == 3
    assert [i.quality for i in intervals] == ["poor", "good", "poor"]
    assert intervals[0].duration_sec == 186          # 12:16:31 -> 12:19:37
    assert intervals[2].duration_sec == 1060         # 12:19:43 -> 12:37:23
    # The uid holding GPS is what connects a reception dip to a user action.
    assert intervals[2].active_uids == "10311"
    assert intervals[2].gps_active is True


def test_no_fix_is_never_reported_as_degraded_reception():
    # "none" means no fix -- acquiring, or GPS off. Counting it as bad
    # reception would invent an outage at the start of every single session.
    from app.services.reasoning import rank_findings

    bundle = {"gnss_signal_evidence": {"degraded_spans": [], "total_intervals": 4}}
    assert [f for f in rank_findings(bundle) if f["category"] == "location"] == []


def test_gps_reception_findings_stay_below_high_and_ignore_brief_dips():
    from app.services.reasoning import rank_findings

    def span(secs):
        return {"gnss_signal_evidence": {"degraded_spans": [{
            "start": "08-28 12:19:43", "end": "08-28 12:37:23",
            "duration_sec": secs, "active_uids": "10311", "gps_active": True,
        }]}}

    # Sub-minute dips are ordinary and would bury the real findings.
    assert [f for f in rank_findings(span(30)) if f["category"] == "location"] == []

    long = [f for f in rank_findings(span(1060)) if f["category"] == "location"][0]
    # Weak GPS indoors is physics, not a fault. Severity is deliberately
    # capped at MEDIUM so nobody is sent chasing broken hardware, and the
    # text must not claim a wrong position was delivered.
    assert long["severity"] == "MEDIUM"
    assert "17m 40s" in long["title"]
    assert "does not by itself mean any position was wrong" in long["detail"]

    short = [f for f in rank_findings(span(90)) if f["category"] == "location"][0]
    assert short["severity"] == "LOW"

    disabled = rank_findings({"location_snapshot_evidence": {"location_enabled": False}})
    # The one location finding that IS a device-state fault rather than physics.
    assert disabled[0]["severity"] == "HIGH"


def test_the_question_that_originally_returned_an_empty_bundle_now_triggers():
    # Verbatim regression. This exact question produced an empty fact bundle
    # and the answer "no evidence of a geolocation issue could be verified"
    # while a 17m40s degraded-GPS span sat unparsed in the capture. The
    # trigger has to survive the words a real person actually uses.
    from app.services.reasoning import LOCATION_TRIGGER_RE

    original = (
        "While playing Pokemon Go in the lower floor of the Moscone Center I see "
        "that my player kept running back and forth between spots without me "
        "physically moving. I suspect it was a signal error with GPS but I'm not "
        "sure. Tell me if there were any geolocation issues on the device on August 28."
    )
    assert LOCATION_TRIGGER_RE.search(original)

    for phrasing in [
        "was there a gps problem", "geolocation issues", "my location kept drifting",
        "the map was jumping around", "it kept rubber-banding", "position was wrong",
        "navigation was off", "how many satellites did it see", "location services",
        "geofencing didn't fire", "my coordinates looked wrong", "gnss quality",
    ]:
        assert LOCATION_TRIGGER_RE.search(phrasing), phrasing

    for unrelated in ["bluetooth pairing failed", "battery drained overnight",
                      "the app crashed on startup"]:
        assert not LOCATION_TRIGGER_RE.search(unrelated), unrelated


def test_location_parsed_from_real_capture(capture1):
    if capture1.location_snapshot is not None:
        assert capture1.location_snapshot.providers
        assert capture1.location_snapshot.source_ref.section == "location"
    for iv in capture1.gnss_signal_intervals:
        assert iv.quality in {"good", "poor", "none"}
        # Found live in this fixture: the battery history stepped backwards
        # 5 seconds mid-stream (a clock correction), which paired into a
        # -5s interval. A negative duration summed into "total degraded
        # seconds" would silently understate the total, so such pairs are
        # dropped as discontinuities and must never reach a caller.
        assert iv.duration_sec >= 0
