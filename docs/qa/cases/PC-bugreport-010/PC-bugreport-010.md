# PC-bugreport-010 — Live rango Disney DLR crash (reference)

Test ID:        PC-bugreport-010
Log type:       Bugreport
Source:         Real user log (anonymized) — Pixel 10 Pro Fold / rango, 2026-09-05; raw zip NOT committed
Scenario:       Live bugreport pulled via adb; ask "Was there a crash on this device? What caused it?"
Ground truth:   Two Java crashes in com.disney.wdpro.dlr — java.lang.RuntimeException: Unable to create application com.disney.wdpro.dlr.DLRApplication at 09-05 21:12:06.659 and 09-05 21:12:13.894. Also 7 native crashes and 1 ANR (package unknown). Parser root_cause_message for the Java crashes is the thin string "25" (Assa Abloy Mobile Keys frame in stack).
Expected parser output:   java_crashes count 2 for com.disney.wdpro.dlr / RuntimeException / Unable to create application ...DLRApplication; native_crashes 7; anrs 1; serial not required for this pin.
Expected narration:       States there were crashes; leads with the Disney DLR RuntimeException (application create failure); may cite Assa Abloy Mobile Keys stack frame as in the fact bundle; must not invent packages for null-attribution natives; confidence MEDIUM; must not invent serial/SSID/BSSID/MAC.
Pass criteria:
  - Stub and live Anthropic/OpenAI diagnose both surface both Disney DLR Java crashes with matching exception/message.
  - Bundle has no serial / ssid / bssid / mac_address keys on this crash path.
  - Narration does not invent a package for natives/ANR where package is null.
  - Does not claim a single crash when multiple categories are present (or clearly scopes most detailed).
Notes: Upload under a fresh device label (e.g. rango-Pixel-10-Pro-Fold), never the mixed historical Pixel label. Live LLM send is a third-party egress — FE letter bar still open until Diagnose/Scan cannot. Screenshots: anthropic_report.png, openai_report.png, ui_device_overview.png (if captured). Raw bugreport zip stays local/gitignored.
