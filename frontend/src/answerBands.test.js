import test from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_VERIFIED_MESSAGE,
  answerConfidence,
  codeOwnedConfidence,
  flattenVerifiedFacts,
  hasVerifiedFacts,
  splitNarrationSections,
} from "./answerBands.js";

test("codeOwnedConfidence never invents a label", () => {
  assert.equal(codeOwnedConfidence("HIGH"), "HIGH");
  assert.equal(codeOwnedConfidence("MEDIUM"), "MEDIUM");
  assert.equal(codeOwnedConfidence(undefined), "UNCONFIRMED");
  assert.equal(codeOwnedConfidence("looks confident"), "UNCONFIRMED");
  assert.equal(codeOwnedConfidence(null), "UNCONFIRMED");
});

test("has evidence path exposes verified facts and code confidence", () => {
  const bundle = {
    has_verified_facts: true,
    answer_confidence: "HIGH",
    verified_facts: [
      {
        category: "crash",
        summary: "Java crash in com.android.systemui",
        confidence: "HIGH",
        source: { section: "system_log", line_start: 10, line_end: 12 },
      },
    ],
  };
  assert.equal(hasVerifiedFacts(bundle), true);
  assert.equal(flattenVerifiedFacts(bundle).length, 1);
  assert.equal(answerConfidence(bundle), "HIGH");
  assert.equal(flattenVerifiedFacts(bundle)[0].source.section, "system_log");
});

test("empty evidence path is honest — no speculative filler", () => {
  const bundle = {
    has_verified_facts: false,
    answer_confidence: "UNCONFIRMED",
    verified_facts: [],
    question: "Should I be worried about that?",
  };
  assert.equal(hasVerifiedFacts(bundle), false);
  assert.deepEqual(flattenVerifiedFacts(bundle), []);
  assert.equal(answerConfidence(bundle), "UNCONFIRMED");
  assert.equal(EMPTY_VERIFIED_MESSAGE, "No verified facts for this question");
});

test("investigation bundles flatten per-capture verified facts", () => {
  const bundle = {
    captures: [
      {
        device_label: "phone",
        verified_facts: [{ category: "wifi", summary: "Wi-Fi disconnection", confidence: "MEDIUM" }],
      },
      {
        device_label: "watch",
        verified_facts: [],
      },
    ],
  };
  const facts = flattenVerifiedFacts(bundle);
  assert.equal(facts.length, 1);
  assert.equal(facts[0].device_label, "phone");
  assert.equal(answerConfidence(bundle), "MEDIUM");
});

test("suggested next steps are split out of narration", () => {
  const report = [
    "## Direct answer",
    "A crash occurred.",
    "",
    "## Suggested next steps",
    "- Check updates",
    "- Clear cache",
  ].join("\n");
  const { narration, nextSteps } = splitNarrationSections(report);
  assert.match(narration, /Direct answer/);
  assert.doesNotMatch(narration, /Suggested next steps/);
  assert.match(nextSteps, /Check updates/);
});
