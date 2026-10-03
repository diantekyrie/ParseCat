import test from "node:test";
import assert from "node:assert/strict";
import {
  HOW_TO_CAPTURE_AOSP_URL,
  HOW_TO_CAPTURE_STEPS,
  HOW_TO_CAPTURE_TITLE,
  howToCaptureCoversEssentials,
  howToCaptureRequiredStepIds,
} from "./howToCapture.js";

test("how-to-capture title is present", () => {
  assert.equal(HOW_TO_CAPTURE_TITLE, "How to capture");
});

test("required Msg8 step ids stay in the guide", () => {
  const ids = howToCaptureRequiredStepIds();
  assert.deepEqual(ids.slice(0, 2), ["hci-before-repro", "full-bugreport"]);
  assert.ok(ids.includes("accepts"));
  assert.ok(ids.includes("limits"));
});

test("essentials: HCI before repro + full bugreport ZIP", () => {
  assert.equal(howToCaptureCoversEssentials(), true);
});

test("essentials fail closed if HCI-before-repro is dropped", () => {
  const stripped = HOW_TO_CAPTURE_STEPS.filter((s) => s.id !== "hci-before-repro");
  assert.equal(howToCaptureCoversEssentials(stripped), false);
});

test("AOSP verify/debug URL is https and points at bluetooth docs", () => {
  assert.match(HOW_TO_CAPTURE_AOSP_URL, /^https:\/\//);
  assert.match(HOW_TO_CAPTURE_AOSP_URL, /bluetooth/i);
  assert.match(HOW_TO_CAPTURE_AOSP_URL, /verifying_debugging/);
});

test("no fabricated sample paths or PII placeholders in step bodies", () => {
  const blob = HOW_TO_CAPTURE_STEPS.map((s) => `${s.title}\n${s.body}`).join("\n");
  assert.doesNotMatch(blob, /frankel|pixel-8|555-01|@gmail\.com|\/Users\//i);
  assert.doesNotMatch(blob, /bugreport-.*-\d{8}/);
});
