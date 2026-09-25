/**
 * Pure helpers for Buganizer-style diagnosis story surfaces.
 *
 * Invent-nothing: every label/field comes from parser/bundle/code-owned
 * confidence. Never invent expected-sequence steps or serials.
 */

import { answerConfidence, flattenVerifiedFacts } from "./answerBands.js";

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const CLASS_SEVERITIES = new Set(Object.keys(SEVERITY_ORDER));

/** Pick identity fields that are actually present — omit missing; never fabricate. */
export function buildIdentityFields({
  deviceContext,
  deviceInfo,
  capture,
  deviceLabel,
} = {}) {
  const ctx = deviceContext && typeof deviceContext === "object" ? deviceContext : {};
  const info = deviceInfo && typeof deviceInfo === "object" ? deviceInfo : {};
  const cap = capture && typeof capture === "object" ? capture : {};

  const manufacturer = firstString(ctx.manufacturer, info.manufacturer);
  const model = firstString(ctx.model, info.model);
  const androidRelease = firstString(ctx.android_release, info.android_release);
  const sdkVersion = firstPresent(ctx.sdk_version, info.sdk_version);
  const buildFingerprint = firstString(ctx.build_fingerprint, info.build_fingerprint);
  const buildId = firstString(ctx.build_id, info.build_id);
  const filename = firstString(cap.original_filename, info.original_filename);
  // Provenance (Arch #64): never label ingested_at as "Captured".
  // Prefer captured_at for Captured; only when that is absent, push a
  // separate Ingested row so the timestamp stays visible but honestly named.
  const capturedAt = firstString(
    formatMaybeDate(cap.captured_at),
    formatMaybeDate(info.captured_at),
  );
  const ingestedAt = firstString(
    formatMaybeDate(cap.ingested_at),
    formatMaybeDate(info.ingested_at),
  );
  const label = firstString(deviceLabel, cap.device_label, info.device_label);

  const fields = [];
  if (label) fields.push({ key: "device", label: "Device", value: label });
  if (manufacturer || model) {
    fields.push({
      key: "product",
      label: "Product",
      value: [manufacturer, model].filter(Boolean).join(" "),
    });
  }
  if (androidRelease || sdkVersion != null) {
    const android = androidRelease
      ? `Android ${androidRelease}${sdkVersion != null ? ` (SDK ${sdkVersion})` : ""}`
      : `SDK ${sdkVersion}`;
    fields.push({ key: "android", label: "Android", value: android });
  }
  if (buildFingerprint) {
    fields.push({ key: "fingerprint", label: "Build fingerprint", value: buildFingerprint });
  } else if (buildId) {
    fields.push({ key: "build", label: "Build", value: buildId });
  }
  if (filename) fields.push({ key: "capture", label: "Capture", value: filename });
  if (capturedAt) {
    fields.push({ key: "captured_at", label: "Captured", value: capturedAt });
  } else if (ingestedAt) {
    fields.push({ key: "ingested_at", label: "Ingested", value: ingestedAt });
  }
  return fields;
}

/**
 * Expected vs Actual contrast.
 * Prefer sequence_check_evidence from the bundle when present.
 * Otherwise Observed-only from deterministic findings/facts — never invent
 * a happy-path Expected sequence. Freeform bundle.expected/actual are NOT
 * a code-owned contract today — do not treat them as explicit mode.
 */
export function buildExpectedVsActual(bundle) {
  if (!bundle || typeof bundle !== "object") {
    return {
      mode: "empty",
      expected: null,
      actual: null,
      note: "No parser findings available yet.",
    };
  }

  const seq = bundle.sequence_check_evidence;
  if (seq && typeof seq === "object" && Array.isArray(seq.steps) && seq.steps.length > 0) {
    const expected = seq.steps.map((s) => ({
      step: String(s.step || s.name || "step"),
      status: s.status || null,
      timestamp: s.timestamp || null,
      capture_id: s.capture_id ?? null,
    }));
    const actual = expected.filter((s) => {
      const st = (s.status || "").toLowerCase();
      return st === "matched" || st.startsWith("failed");
    });
    return {
      mode: "sequence_check",
      sequence: seq.sequence || null,
      expected,
      actual,
      note: null,
    };
  }

  // Invent-nothing: ignore freeform bundle.expected / bundle.actual until
  // build_diagnosis_bundle / diagnose_investigation emit them as a documented
  // code-owned contract. Fall through to observed-only / empty.
  const observed = pickObservedText(bundle);
  if (!observed) {
    return {
      mode: "empty",
      expected: null,
      actual: null,
      note: "No expected-sequence check is available yet, and no verified observations to contrast.",
    };
  }

  return {
    mode: "observed_only",
    expected: null,
    actual: observed,
    note: "Expected (not in this capture): no expected-sequence check is available yet — Observed below is from parser findings/verified facts only.",
  };
}

/** Ordered cited steps from verified facts / ranked findings (parser ground truth). */
export function buildCitedTimeline(bundle, { limit = 24 } = {}) {
  const facts = flattenVerifiedFacts(bundle);
  const findings = Array.isArray(bundle?.ranked_findings) ? bundle.ranked_findings : [];
  const events = Array.isArray(bundle?.timeline) ? bundle.timeline : [];

  const rows = [];

  for (const f of facts) {
    const label = firstString(f.summary, f.detail);
    if (!label) continue;
    rows.push({
      kind: "verified",
      timestamp: f.timestamp || null,
      label,
      category: f.category || null,
      severity: null,
      source: f.source || null,
      original_filename: f.original_filename || null,
      device_label: f.device_label || null,
      sortKey: timelineSortKey(f.timestamp),
    });
  }

  for (const f of findings) {
    const label = firstString(f.title, f.detail);
    if (!label) continue;
    const ts = f.timestamp || f.first_timestamp || null;
    // Skip duplicates already covered by verified facts with same summary+ts
    const dup = rows.some(
      (r) => r.label === label && (r.timestamp || null) === (ts || null),
    );
    if (dup) continue;
    rows.push({
      kind: "finding",
      timestamp: ts,
      label,
      category: f.category || null,
      severity: CLASS_SEVERITIES.has(f.severity) ? f.severity : null,
      source: f.source || null,
      original_filename: f.original_filename || null,
      device_label: f.device_label || null,
      sortKey: timelineSortKey(ts),
    });
  }

  for (const e of events) {
    const label = firstString(e.label, e.summary);
    if (!label) continue;
    rows.push({
      kind: "event",
      timestamp: e.timestamp || null,
      label,
      category: e.kind || e.category || null,
      severity: e.severity || null,
      source: e.source || null,
      original_filename: e.original_filename || null,
      device_label: e.device_label || null,
      sortKey: timelineSortKey(e.timestamp),
    });
  }

  rows.sort((a, b) => {
    if (a.sortKey !== b.sortKey) return a.sortKey < b.sortKey ? -1 : 1;
    return 0;
  });

  return rows.slice(0, limit).map(({ sortKey, ...rest }) => rest);
}

/**
 * Classification chip from code-owned fields only (severity/category/confidence).
 * Never from freeform LLM prose.
 */
export function buildClassification(bundle) {
  const confidence = answerConfidence(bundle);
  const findings = Array.isArray(bundle?.ranked_findings) ? bundle.ranked_findings : [];
  const top = pickTopFinding(findings);
  const facts = flattenVerifiedFacts(bundle);

  if (top) {
    return {
      label: [top.severity, top.category].filter(Boolean).join(" · ") || "Unconfirmed",
      severity: CLASS_SEVERITIES.has(top.severity) ? top.severity : null,
      category: top.category || null,
      confidence,
      source: "ranked_finding",
    };
  }

  const factWithCat = facts.find((f) => f.category);
  if (factWithCat) {
    return {
      label: String(factWithCat.category),
      severity: null,
      category: factWithCat.category,
      confidence,
      source: "verified_fact",
    };
  }

  if (confidence && confidence !== "UNCONFIRMED") {
    return {
      label: confidence,
      severity: null,
      category: null,
      confidence,
      source: "answer_confidence",
    };
  }

  return {
    label: "Unconfirmed",
    severity: null,
    category: null,
    confidence: "UNCONFIRMED",
    source: "empty",
  };
}

function pickTopFinding(findings) {
  if (!findings.length) return null;
  return [...findings].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.severity] ?? 99;
    return sa - sb;
  })[0];
}

function pickObservedText(bundle) {
  const findings = Array.isArray(bundle.ranked_findings) ? bundle.ranked_findings : [];
  const top = pickTopFinding(findings);
  if (top) {
    const parts = [top.title, top.detail].filter(Boolean);
    return parts.join(" — ") || null;
  }
  const facts = flattenVerifiedFacts(bundle);
  if (facts.length > 0) {
    const f = facts[0];
    return firstString(f.summary, f.detail);
  }
  return null;
}

function firstString(...vals) {
  for (const v of vals) {
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return null;
}

function firstPresent(...vals) {
  for (const v of vals) {
    if (v !== null && v !== undefined && v !== "") return v;
  }
  return null;
}

function formatMaybeDate(v) {
  if (v == null) return null;
  if (typeof v === "string" && v.trim()) return v.trim();
  if (v instanceof Date && !Number.isNaN(v.getTime())) return v.toISOString();
  return null;
}

function timelineSortKey(ts) {
  if (!ts || typeof ts !== "string") return "\uffff"; // undated last
  return ts;
}
