/** "Narrated by" provider-dropdown option state (#87).
 *
 * Extracted out of App.jsx so this logic is unit-testable under the
 * project's plain `node --test` runner, which cannot import a .jsx file
 * directly -- before this, the only verification on record was Cat QA's
 * headed click-through (2026-10-17), not a regression test that runs in
 * CI. Arch review on #123 flagged the missing test; this file plus
 * providerOptions.test.js is the fix.
 *
 * Issue #87: the "Narrated by" dropdown used to read ONLY p.available/
 * p.disabled_reason from GET /api/llm/providers, which reflects the
 * OPERATOR's own server-env key -- it had no idea a user had saved their
 * own BYOK key for that provider, so it kept showing "(no key set)" and
 * disabling the option even though Settings correctly said "Saved to your
 * account" and the backend (_resolve_byok) would actually use it. A saved
 * BYOK key always wins over the operator's key when both exist (see
 * _resolve_byok), so these two helpers check byokStatus FIRST.
 */

export function providerOptionLabel(p, byokStatus) {
  if (byokStatus?.[p.id]?.configured) return `${p.label} (your key)`;
  if (p.available) return p.label;
  return `${p.label}${p.disabled_reason === "egress_gated" ? " (third-party send disabled)" : " (no key set)"}`;
}

export function providerOptionDisabled(p, byokStatus) {
  return !p.available && !byokStatus?.[p.id]?.configured;
}
