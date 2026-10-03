# How to capture for ParseCat

ParseCat diagnoses from **structured facts** extracted from Android
bugreports (and optional packet captures). A capture taken the wrong way
often parses cleanly but has **empty Bluetooth HCI / dumpsys sections**,
which looks like "ParseCat found nothing" when the device never recorded
the evidence.

This guide covers the two capture mistakes that matter most for Bluetooth
and full-platform diagnosis. It does **not** claim every OEM matches the
AOSP paths below — labels and folders vary; Prefer uploading the **whole
bugreport ZIP** and let ParseCat search known locations.

No sample captures, serials, or personal data belong in this doc.

## 1. Take a full bugreport (not plain logcat)

Prefer a **bugreport ZIP**. ParseCat's parsers for battery, memory, thermal,
SELinux, process kills, Wi-Fi framework state, companion device, and more
read `dumpsys` / EVENT LOG sections that only exist in a full bugreport.
Plain `adb logcat` text usually will not.

### From a computer (recommended)

With USB debugging authorized (or wireless debugging connected):

```bash
adb devices
adb bugreport bugreport.zip
```

Upload the resulting `.zip` to ParseCat under a device label.

### From the phone UI

1. Enable **Developer options** (tap **Build number** seven times under
   Settings → About phone — exact menu path varies by OEM).
2. Open **Developer options**.
3. Use **Take bug report** / **Bug report** (wording varies). Choose the
   interactive / full report when offered.
4. Wait for the notification, then share or copy the ZIP off the device.

### What ParseCat accepts

| Upload | What you get |
|---|---|
| `.zip` bugreport | Full text sections **plus** ZIP-contained companions (tombstones, ANRs, Bluetooth HCI log files when present). |
| `.txt` flattened bugreport | Text sections only. Tombstones / ANRs / HCI files that live as separate ZIP members are **unavailable**. |
| `.pcap` / `.pcapng` | Packet-capture container + protocol analysis (separate from bugreport HCI). |
| Plain logcat dump | Usually **not** enough — ParseCat will warn when the file looks like log lines with no bugreport section markers. |

`.btt` (Ellisys) is **not** supported.

## 2. Enable Bluetooth HCI snoop **before** you reproduce

Bluetooth HCI evidence lives in an on-device **btsnoop** log that ParseCat
reads from the bugreport ZIP (typical AOSP location under
`data/misc/bluetooth/logs/`; inside the ZIP this often appears as
`FS/data/misc/bluetooth/logs/…`). Filenames vary by OEM/build
(`btsnoop_hci.log`, `btsnoop_hci.log.filtered`, rotated `.last` copies,
etc.) — see `BT_HCI_LOG_CANDIDATES` in `backend/app/services/ingestion.py`.

**If HCI snoop was off during the failure, a later bugreport cannot invent
those packets.** Enable it, restart Bluetooth, then reproduce, then take
the bugreport.

### Steps (AOSP Developer options)

Documented by AOSP for Android 4.4+:

1. Enable **Developer options** on the device.
2. In **Developer options**, turn on **Enable Bluetooth HCI snoop log**
   (OEM label may differ slightly; it stays under Developer options).
3. **Restart Bluetooth** (toggle off, then on) so logging takes effect.
4. Reproduce the Bluetooth issue.
5. Take a **bugreport ZIP** (section 1) while the issue is still fresh.
6. Upload the ZIP to ParseCat.
7. When finished debugging, turn HCI snoop **off** again (privacy /
   storage).

AOSP notes that always-on in-memory BTSnoop only keeps non-personal events;
the Developer-options toggle is what enables fuller HCI logging. See
[AOSP — Verify and debug (Bluetooth)](https://source.android.com/docs/core/connect/bluetooth/verifying_debugging).

### What ParseCat does **not** claim here

- Enabling snoop does not guarantee every OEM writes a classic `btsnoop`
  file ParseCat can decode; when none is found, ParseCat reports
  `No Bluetooth HCI snoop log found` (or a format mismatch warning).
- A `.txt`-only upload cannot include the ZIP-resident HCI file.
- HCI framing decode covers load-bearing connection / disconnect / command
  status events — **not** full L2CAP / profile disassembly (see README).

## Quick checklist

- [ ] HCI snoop enabled **before** the Bluetooth repro (if BT is in scope)
- [ ] Bluetooth toggled off/on after enabling snoop
- [ ] Failure reproduced
- [ ] Full **bugreport ZIP** taken afterward (`adb bugreport` or Developer options)
- [ ] Whole ZIP uploaded to ParseCat (not a hand-extracted subset unless you know you need only a `.pcap`)

## Related

- README — Architecture / Upload formats / Bluetooth HCI decoding limits
- Dashboard sidebar — **How to capture** panel (same checklist, condensed)
