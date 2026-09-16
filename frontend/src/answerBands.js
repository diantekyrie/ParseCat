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
