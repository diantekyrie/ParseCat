import test from "node:test";
import assert from "node:assert/strict";
import {
  buildIdentityFields,
  buildExpectedVsActual,
  buildCitedTimeline,
  buildClassification,
} from "./diagnosisStory.js";

test("buildIdentityFields omits missing fields and never fabricates serials", () => {
  const fields = buildIdentityFields({
    deviceContext: { manufacturer: "Google", model: "Pixel 8", android_release: "14", sdk_version: 34 },
    capture: { original_filename: "bugreport.zip", captured_at: "2026-09-01T12:00:00Z" },
    deviceLabel: "lab-phone",
  });
  const byKey = Object.fromEntries(fields.map((f) => [f.key, f.value]));
  assert.equal(byKey.device, "lab-phone");
  assert.equal(byKey.product, "Google Pixel 8");
  assert.match(byKey.android, /Android 14/);
  assert.equal(byKey.capture, "bugreport.zip");
  assert.ok(byKey.captured_at);
  assert.equal(fields.find((f) => /serial/i.test(f.label)), undefined);
});

test("buildIdentityFields returns empty when nothing present", () => {
  assert.deepEqual(buildIdentityFields({}), []);
  assert.deepEqual(buildIdentityFields(), []);
});

test("buildIdentityFields: ingested_at alone never produces a Captured field", () => {
  const fields = buildIdentityFields({
    capture: { original_filename: "bugreport.zip", ingested_at: "2026-09-20T08:00:00Z" },
  });
  const byKey = Object.fromEntries(fields.map((f) => [f.key, f]));
  assert.equal(byKey.captured_at, undefined);
  assert.equal(fields.find((f) => f.label === "Captured"), undefined);
  assert.equal(byKey.ingested_at.label, "Ingested");
  assert.equal(byKey.ingested_at.value, "2026-09-20T08:00:00Z");
});

test("buildIdentityFields: captured_at prefers Captured and does not also emit Ingested", () => {
  const fields = buildIdentityFields({
    capture: {
      captured_at: "2026-09-01T12:00:00Z",
      ingested_at: "2026-09-20T08:00:00Z",
    },
  });
  const byKey = Object.fromEntries(fields.map((f) => [f.key, f]));
  assert.equal(byKey.captured_at.label, "Captured");
  assert.equal(byKey.captured_at.value, "2026-09-01T12:00:00Z");
  assert.equal(byKey.ingested_at, undefined);
});

test("buildExpectedVsActual is invent-nothing: observed-only without sequence_check", () => {
  const contrast = buildExpectedVsActual({
    ranked_findings: [
      {
        severity: "CRITICAL",
        category: "crash",
        title: "Java crash in com.android.systemui",
        detail: "NullPointerException",
        confidence: "HIGH",
        source: { section: "system_log", line_start: 10, line_end: 12 },
      },
    ],
  });
  assert.equal(contrast.mode, "observed_only");
  assert.equal(contrast.expected, null);
  assert.match(contrast.actual, /Java crash/);
  assert.match(contrast.note, /no expected-sequence check/i);
});

test("buildExpectedVsActual empty when no findings", () => {
  const contrast = buildExpectedVsActual({ verified_facts: [], ranked_findings: [] });
  assert.equal(contrast.mode, "empty");
  assert.equal(contrast.actual, null);
  assert.equal(contrast.expected, null);
});

test("buildExpectedVsActual uses sequence_check_evidence when present", () => {
  const contrast = buildExpectedVsActual({
    sequence_check_evidence: {
      sequence: "wifi_assoc",
      steps: [
        { step: "scan", status: "matched", timestamp: "10:00:01" },
        { step: "auth", status: "not_reached" },
      ],
    },
  });
  assert.equal(contrast.mode, "sequence_check");
  assert.equal(contrast.sequence, "wifi_assoc");
  assert.equal(contrast.expected.length, 2);
  assert.equal(contrast.expected[1].status, "not_reached");
});

test("buildExpectedVsActual: freeform expected/actual keys do not switch to explicit mode", () => {
  const withFindings = buildExpectedVsActual({
    expected: "phone pairs cleanly",
    actual: "pairing failed",
    ranked_findings: [
      {
        severity: "HIGH",
        category: "bluetooth",
        title: "Pairing failure",
        detail: "bond state BOND_NONE",
        confidence: "HIGH",
      },
    ],
  });
  assert.notEqual(withFindings.mode, "explicit");
  assert.equal(withFindings.mode, "observed_only");
  assert.match(withFindings.actual, /Pairing failure/);

  const freeformOnly = buildExpectedVsActual({
    expected: "should work",
    actual: "did not work",
  });
  assert.notEqual(freeformOnly.mode, "explicit");
  assert.equal(freeformOnly.mode, "empty");
  assert.equal(freeformOnly.expected, null);
  assert.equal(freeformOnly.actual, null);
});

test("buildClassification never invents from prose — Unconfirmed when empty", () => {
  const empty = buildClassification({});
  assert.equal(empty.label, "Unconfirmed");
  assert.equal(empty.confidence, "UNCONFIRMED");
  assert.equal(empty.source, "empty");
});

test("buildClassification prefers top ranked finding severity · category", () => {
  const cls = buildClassification({
    answer_confidence: "HIGH",
    ranked_findings: [
      { severity: "MEDIUM", category: "wifi", title: "disconnect" },
      { severity: "CRITICAL", category: "crash", title: "crash" },
    ],
  });
  assert.equal(cls.label, "CRITICAL · crash");
  assert.equal(cls.severity, "CRITICAL");
  assert.equal(cls.confidence, "HIGH");
  assert.equal(cls.source, "ranked_finding");
});

test("buildCitedTimeline orders by timestamp and keeps citations", () => {
  const rows = buildCitedTimeline({
    verified_facts: [
      {
        category: "wifi",
        summary: "Wi-Fi disconnection",
        timestamp: "10:00:02",
        confidence: "MEDIUM",
        source: { section: "wifi", line_start: 5, line_end: 5 },
        original_filename: "a.zip",
      },
      {
        category: "crash",
        summary: "Java crash",
        timestamp: "10:00:01",
        confidence: "HIGH",
        source: { section: "system_log", line_start: 1, line_end: 2 },
      },
    ],
  });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].label, "Java crash");
  assert.equal(rows[1].label, "Wi-Fi disconnection");
  assert.equal(rows[1].source.section, "wifi");
  assert.equal(rows[1].original_filename, "a.zip");
});

test("buildCitedTimeline filters empty labels", () => {
  const rows = buildCitedTimeline({
    verified_facts: [{ category: "x", summary: "", confidence: "LOW" }],
    ranked_findings: [{ severity: "LOW", category: "y", title: "" }],
  });
  assert.equal(rows.length, 0);
});
