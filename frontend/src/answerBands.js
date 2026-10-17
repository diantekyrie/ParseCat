/** Code-owned helpers for Diagnose/Scan Verified-from-log vs Narration bands.
 *
 * Confidence chips and empty-evidence honesty live here so the UI cannot
 * invent labels or fill gaps with speculative RCA.
 */

export const EMPTY_VERIFIED_MESSAGE = "No verified facts for this question";
export const NEXT_STEPS_LABEL = "Suggested next steps — not verified / general troubleshooting";

const CONFIDENCE_LABELS = new Set(["HIGH", "MEDIUM", "LOW", "UNCONFIRMED"]);

export function codeOwnedConfidence(raw) {
  return CONFIDENCE_LABELS.has(raw) ? raw : "UNCONFIRMED";
}

/** Flatten verified_facts from a diagnose/scan/investigation bundle. */
export function flattenVerifiedFacts(bundle) {
  if (!bundle || typeof bundle !== "object") return [];
  if (Array.isArray(bundle.verified_facts)) return bundle.verified_facts;
  if (Array.isArray(bundle.captures)) {
    return bundle.captures.flatMap((cap) => {
      if (!cap || typeof cap !== "object") return [];
      const label = cap.device_label;
      return (cap.verified_facts || []).map((f) => (
        label ? { ...f, device_label: f.device_label || label } : f
      ));
    });
  }
  return [];
}

export function answerConfidence(bundle) {
  if (bundle && typeof bundle.answer_confidence === "string") {
    return codeOwnedConfidence(bundle.answer_confidence);
  }
  const facts = flattenVerifiedFacts(bundle);
  if (facts.length === 0) return "UNCONFIRMED";
  const rank = { HIGH: 0, MEDIUM: 1, LOW: 2, UNCONFIRMED: 3 };
  return facts
    .map((f) => codeOwnedConfidence(f.confidence))
    .reduce((best, cur) => (rank[cur] < rank[best] ? cur : best), "UNCONFIRMED");
}

export function hasVerifiedFacts(bundle) {
  if (bundle && typeof bundle.has_verified_facts === "boolean") {
    return bundle.has_verified_facts;
  }
  return flattenVerifiedFacts(bundle).length > 0;
}

/** Split LLM report markdown into narration body vs suggested-next-steps. */
export function splitNarrationSections(reportText) {
  if (!reportText || typeof reportText !== "string") {
    return { narration: "", nextSteps: "" };
  }
  const marker = /^##\s+Suggested next steps\s*$/im;
  const match = marker.exec(reportText);
  if (!match) {
    return { narration: reportText, nextSteps: "" };
  }
  return {
    narration: reportText.slice(0, match.index).trimEnd(),
    nextSteps: reportText.slice(match.index + match[0].length).trim(),
  };
}

/** "Narrated by" source label (#84).
 *
 * The backend echoes the REQUESTED `provider` (e.g. "stub" from the
 * dropdown) but a BYOK key overrides it, so that echo must never be used as
 * the source label when `narrated_by` (the provider that actually ran) is
 * available. Rules:
 *   - `narrated_by` present and non-empty -> label for that id
 *     ("openrouter-byok" -> "OpenRouter (your key)").
 *   - `narrated_by` present but null -> no label (narration failed or the
 *     backend could not resolve what ran) rather than a guessed one.
 *   - `narrated_by` absent (older backend) -> fall back to `provider`, but
 *     only when this request did not carry a BYOK key (`byok_sent`), since
 *     then `provider` is not what ran.
 *   - A BYOK request never gets the Stub label.
 */
export const BYOK_PROVIDER_ID = "openrouter-byok";
export const BYOK_PROVIDER_LABEL = "OpenRouter (your key)";
export const UNKNOWN_NARRATOR_EXPORT = "unknown (no narration, or source not reported)";

function labelForId(id, providers) {
  if (id === BYOK_PROVIDER_ID) return BYOK_PROVIDER_LABEL;
  const match = (providers || []).find((p) => p && p.id === id);
  return (match && match.label) || id;
}

export function narratedByLabel(result, providers = []) {
  if (!result || typeof result !== "object") return null;
  const byokSent = result.byok_sent === true;
  let id;
  if (Object.prototype.hasOwnProperty.call(result, "narrated_by")) {
    id = result.narrated_by;
  } else {
    id = byokSent ? null : result.provider;
  }
  if (typeof id !== "string" || !id) return null;
  if (byokSent && id === "stub") return null;
  return labelForId(id, providers);
}

/** Export header line; uses the same rules so an export can't claim Stub
 * over live text. */
export function narratedByExportLine(result, providers = []) {
  return `narrated by: ${narratedByLabel(result, providers) || UNKNOWN_NARRATOR_EXPORT}`;
}
