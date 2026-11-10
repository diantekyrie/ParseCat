import test from "node:test";
import assert from "node:assert/strict";
import { providerOptionDisabled, providerOptionLabel } from "./providerOptions.js";

// Arch review on #123: this behavior (#87's fix) had no unit test before --
// only Cat QA's headed click-through on the live deploy (2026-10-17), which
// doesn't run in CI and wouldn't catch a future regression.

test("a saved BYOK key wins over the operator's own key state", () => {
  const anthropic = { id: "anthropic", label: "Claude (Anthropic)", available: false, disabled_reason: "no_key" };
  const byokStatus = { anthropic: { configured: true, model: null } };

  assert.equal(providerOptionLabel(anthropic, byokStatus), "Claude (Anthropic) (your key)");
  assert.equal(providerOptionDisabled(anthropic, byokStatus), false);
});

test("no saved key and no operator key -> disabled, labelled no key set", () => {
  const anthropic = { id: "anthropic", label: "Claude (Anthropic)", available: false, disabled_reason: "no_key" };
  const byokStatus = { anthropic: { configured: false, model: null } };

  assert.equal(providerOptionLabel(anthropic, byokStatus), "Claude (Anthropic) (no key set)");
  assert.equal(providerOptionDisabled(anthropic, byokStatus), true);
});

test("operator key available, no saved BYOK key -> enabled, plain label", () => {
  const anthropic = { id: "anthropic", label: "Claude (Anthropic)", available: true, disabled_reason: null };
  const byokStatus = { anthropic: { configured: false, model: null } };

  assert.equal(providerOptionLabel(anthropic, byokStatus), "Claude (Anthropic)");
  assert.equal(providerOptionDisabled(anthropic, byokStatus), false);
});

test("egress-gated operator key (no saved BYOK key) gets its own wording", () => {
  const anthropic = { id: "anthropic", label: "Claude (Anthropic)", available: false, disabled_reason: "egress_gated" };
  const byokStatus = { anthropic: { configured: false, model: null } };

  assert.equal(providerOptionLabel(anthropic, byokStatus), "Claude (Anthropic) (third-party send disabled)");
  assert.equal(providerOptionDisabled(anthropic, byokStatus), true);
});

test("a saved key overrides egress-gated wording too -- own key still usable", () => {
  const anthropic = { id: "anthropic", label: "Claude (Anthropic)", available: false, disabled_reason: "egress_gated" };
  const byokStatus = { anthropic: { configured: true, model: null } };

  assert.equal(providerOptionLabel(anthropic, byokStatus), "Claude (Anthropic) (your key)");
  assert.equal(providerOptionDisabled(anthropic, byokStatus), false);
});

test("missing byokStatus entry for this provider behaves like not configured", () => {
  const openrouter = { id: "openrouter", label: "OpenRouter (multi-model gateway)", available: false, disabled_reason: "no_key" };
  assert.equal(providerOptionLabel(openrouter, {}), "OpenRouter (multi-model gateway) (no key set)");
  assert.equal(providerOptionDisabled(openrouter, {}), true);
  // Also tolerate byokStatus being entirely absent (undefined).
  assert.equal(providerOptionLabel(openrouter, undefined), "OpenRouter (multi-model gateway) (no key set)");
  assert.equal(providerOptionDisabled(openrouter, undefined), true);
});

test("stub (not BYOK-capable) with no byokStatus entry just reports operator availability", () => {
  const stub = { id: "stub", label: "Stub (no LLM, echoes facts)", available: true, disabled_reason: null };
  assert.equal(providerOptionLabel(stub, {}), "Stub (no LLM, echoes facts)");
  assert.equal(providerOptionDisabled(stub, {}), false);
});
