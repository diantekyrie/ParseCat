/**
 * Condensed how-to-capture copy for the dashboard.
 * Keep invent-nothing: steps mirror AOSP Developer-options HCI snoop +
 * adb bugreport; OEM menu labels/paths may differ. No sample PII.
 *
 * Full write-up: docs/how-to-capture.md
 */

export const HOW_TO_CAPTURE_TITLE = "How to capture";

export const HOW_TO_CAPTURE_INTRO =
  "Empty HCI or dumpsys sections usually mean the device never recorded them — not that ParseCat \"missed\" the file. Enable the right toggles before repro, then upload a full bugreport ZIP.";

/** Ordered checklist rows shown in the sidebar panel. */
export const HOW_TO_CAPTURE_STEPS = [
  {
    id: "hci-before-repro",
    title: "Bluetooth: enable HCI snoop before repro",
    body:
      "Developer options → Enable Bluetooth HCI snoop log (label varies by OEM). Toggle Bluetooth off/on so logging starts. Reproduce the issue, then take the bugreport. Turning snoop on after the failure cannot invent packets.",
  },
  {
    id: "full-bugreport",
    title: "Take a full bugreport ZIP",
    body:
      "Prefer `adb bugreport bugreport.zip`, or Developer options → Take bug report. Upload the whole .zip. Plain logcat / .txt-only uploads lack ZIP companions (tombstones, ANRs, HCI files).",
  },
  {
    id: "accepts",
    title: "What ParseCat accepts",
    body:
      ".zip bugreport (best), flattened .txt (no ZIP-only companions), .pcap/.pcapng. .btt is not supported. OEM HCI paths vary; ParseCat searches known btsnoop names under the bugreport's bluetooth logs folder.",
  },
  {
    id: "limits",
    title: "Honest limits",
    body:
      "If snoop was off or the OEM wrote no classic btsnoop file, ParseCat reports that HCI was not found — it does not invent traffic. HCI decode here is framing-level (connect/disconnect/command status), not full L2CAP/profile disassembly.",
  },
];

export const HOW_TO_CAPTURE_DOCS_HINT =
  "Full steps and AOSP link: docs/how-to-capture.md in the repo.";

export const HOW_TO_CAPTURE_AOSP_URL =
  "https://source.android.com/docs/core/connect/bluetooth/verifying_debugging";

/**
 * Returns a stable list of step ids — used by tests so UI copy refactors
 * cannot silently drop the HCI-before-repro or bugreport requirements.
 */
export function howToCaptureRequiredStepIds() {
  return HOW_TO_CAPTURE_STEPS.map((s) => s.id);
}

/**
 * True when the condensed guide still teaches the two Msg8 capture rules.
 */
export function howToCaptureCoversEssentials(steps = HOW_TO_CAPTURE_STEPS) {
  const byId = Object.fromEntries(steps.map((s) => [s.id, s]));
  const hci = byId["hci-before-repro"];
  const bug = byId["full-bugreport"];
  if (!hci || !bug) return false;
  const hciText = `${hci.title} ${hci.body}`.toLowerCase();
  const bugText = `${bug.title} ${bug.body}`.toLowerCase();
  return (
    hciText.includes("before") &&
    hciText.includes("hci") &&
    hciText.includes("snoop") &&
    bugText.includes("bugreport") &&
    (bugText.includes(".zip") || bugText.includes("zip"))
  );
}
