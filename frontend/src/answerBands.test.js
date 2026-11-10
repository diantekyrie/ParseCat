import test from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_VERIFIED_MESSAGE,
  UNKNOWN_NARRATOR_EXPORT,
  answerConfidence,
  byokProviderId,
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
  { id: "anthropic", label: "Claude (Anthropic)" },
  { id: "openrouter", label: "OpenRouter (multi-model gateway)" },
  { id: "stub", label: "Stub (no LLM, echoes facts)" },
];

test("narratedByLabel prefers narrated_by over the echoed provider", () => {
  const byokScan = { provider: "stub", narrated_by: byokProviderId("openrouter"), byok_sent: true };
  assert.equal(narratedByLabel(byokScan, PROVIDERS), "OpenRouter (multi-model gateway) (your key)");
  assert.equal(
    narratedByLabel({ provider: "stub", narrated_by: "openrouter" }, PROVIDERS),
    "OpenRouter (multi-model gateway)",
  );
  assert.equal(narratedByLabel({ provider: null, narrated_by: "stub" }, PROVIDERS), "Stub (no LLM, echoes facts)");
});

test("BYOK label is per-provider, not a single OpenRouter-shaped constant", () => {
  // Arch review on #123: before byok_narrated_by()/byokProviderId(), every
  // BYOK provider's id and label collapsed onto OpenRouter's. A saved
  // Anthropic key must label as Anthropic's own "(your key)" text, not
  // OpenRouter's -- the cross-provider case that was wrong before this fix.
  const anthropicByok = { provider: "stub", narrated_by: byokProviderId("anthropic"), byok_sent: true };
  const label = narratedByLabel(anthropicByok, PROVIDERS);
  assert.equal(label, "Claude (Anthropic) (your key)");
  assert.doesNotMatch(label, /openrouter/i);
});

test("BYOK id never maps to Stub, even if providers list is odd", () => {
  // The weird entry sits at the full suffixed id ("openrouter-byok"), but
  // labelForId strips the "-byok" suffix BEFORE searching providers, so it
  // only ever looks up the base id ("openrouter") -- this weird entry is
  // never consulted at all, not even accidentally. No "openrouter" entry
  // exists here, so the degraded fallback is the raw base id, never Stub.
  const byokId = byokProviderId("openrouter");
  const weird = [{ id: byokId, label: "Stub (no LLM, echoes facts)" }];
  const label = narratedByLabel({ provider: "stub", narrated_by: byokId }, weird);
  assert.equal(label, "openrouter (your key)");
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
  const byok = { provider: "stub", narrated_by: byokProviderId("openrouter"), byok_sent: true };
  assert.equal(narratedByExportLine(byok, PROVIDERS), "narrated by: OpenRouter (multi-model gateway) (your key)");
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
