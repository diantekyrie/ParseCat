import test from "node:test";
import assert from "node:assert/strict";
import {
  BYOK_PROVIDER_ID,
  BYOK_PROVIDER_LABEL,
  EMPTY_VERIFIED_MESSAGE,
  UNKNOWN_NARRATOR_EXPORT,
  answerConfidence,
  codeOwnedConfidence,
  flattenVerifiedFacts,
  hasVerifiedFacts,
  narratedByExportLine,
  narratedByLabel,
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

// --- #84 narrated-by label ---------------------------------------------

const PROVIDERS = [
  { id: "openrouter", label: "OpenRouter (multi-model gateway)" },
  { id: "stub", label: "Stub (no LLM, echoes facts)" },
];

test("narratedByLabel prefers narrated_by over the echoed provider", () => {
  const byokScan = { provider: "stub", narrated_by: BYOK_PROVIDER_ID, byok_sent: true };
  assert.equal(narratedByLabel(byokScan, PROVIDERS), "OpenRouter (your key)");
  assert.equal(BYOK_PROVIDER_LABEL, "OpenRouter (your key)");
  assert.equal(
    narratedByLabel({ provider: "stub", narrated_by: "openrouter" }, PROVIDERS),
    "OpenRouter (multi-model gateway)",
  );
  assert.equal(narratedByLabel({ provider: null, narrated_by: "stub" }, PROVIDERS), "Stub (no LLM, echoes facts)");
});

test("BYOK id never maps to Stub, even if providers list is odd", () => {
  const weird = [{ id: BYOK_PROVIDER_ID, label: "Stub (no LLM, echoes facts)" }];
  const label = narratedByLabel({ provider: "stub", narrated_by: BYOK_PROVIDER_ID }, weird);
  assert.equal(label, BYOK_PROVIDER_LABEL);
  assert.doesNotMatch(label, /stub/i);
});

test("a BYOK request is never labelled Stub", () => {
  // Older backend (no narrated_by field): provider echo is not trusted.
  assert.equal(narratedByLabel({ provider: "stub", byok_sent: true }, PROVIDERS), null);
  // Inconsistent narrated_by=stub on a BYOK request: refuse to claim Stub.
  assert.equal(narratedByLabel({ provider: "stub", narrated_by: "stub", byok_sent: true }, PROVIDERS), null);
});

test("null narrated_by shows no label instead of falling back to the requested provider", () => {
  assert.equal(narratedByLabel({ provider: "stub", narrated_by: null, byok_sent: true }, PROVIDERS), null);
  assert.equal(narratedByLabel({ provider: "anthropic", narrated_by: null }, PROVIDERS), null);
});

test("older backend without narrated_by and no BYOK falls back to provider", () => {
  assert.equal(narratedByLabel({ provider: "stub" }, PROVIDERS), "Stub (no LLM, echoes facts)");
  assert.equal(narratedByLabel({ provider: null }, PROVIDERS), null);
  assert.equal(narratedByLabel(null, PROVIDERS), null);
  assert.equal(narratedByLabel({ narrated_by: "anthropic" }, []), "anthropic");
});

test("export header line uses narrated_by and never claims Stub over BYOK text", () => {
  const byok = { provider: "stub", narrated_by: BYOK_PROVIDER_ID, byok_sent: true };
  assert.equal(narratedByExportLine(byok, PROVIDERS), "narrated by: OpenRouter (your key)");
  assert.doesNotMatch(narratedByExportLine(byok, PROVIDERS), /stub/i);
  assert.equal(
    narratedByExportLine({ provider: "stub", narrated_by: null, byok_sent: true }, PROVIDERS),
    `narrated by: ${UNKNOWN_NARRATOR_EXPORT}`,
  );
  assert.equal(
    narratedByExportLine({ provider: null, narrated_by: "stub" }, PROVIDERS),
    "narrated by: Stub (no LLM, echoes facts)",
  );
});
