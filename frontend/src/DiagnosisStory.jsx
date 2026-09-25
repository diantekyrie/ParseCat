/**
 * Buganizer-style customer-facing result surfaces for Diagnose/Scan.
 * Parser truth leads; narration stays subordinate (rendered after by App).
 */

import {
  buildClassification,
  buildCitedTimeline,
  buildExpectedVsActual,
  buildIdentityFields,
} from "./diagnosisStory.js";

const FINDING_TONE = {
  CRITICAL: "var(--red)",
  HIGH: "var(--orange)",
  MEDIUM: "var(--amber)",
  LOW: "var(--blue)",
};
const CONFIDENCE_COLOR = {
  HIGH: "var(--green)",
  MEDIUM: "var(--amber)",
  LOW: "var(--orange)",
  UNCONFIRMED: "var(--muted)",
};

function SourceCite({ source }) {
  if (!source || !source.section) return null;
  return (
    <span className="src">
      {source.section}:{source.line_start}
      {source.line_end !== source.line_start ? `-${source.line_end}` : ""}
    </span>
  );
}

function CaptureCite({ filename }) {
  if (!filename) return null;
  const short = filename.length > 30 ? `${filename.slice(0, 27)}…` : filename;
  return <span className="capture-tag" title={filename}>{short}</span>;
}

/** Compact identity strip from parser/device fields only. */
export function IdentityStrip({
  deviceContext,
  deviceInfo,
  capture,
  deviceLabel,
  compact = false,
}) {
  const fields = buildIdentityFields({ deviceContext, deviceInfo, capture, deviceLabel });
  if (fields.length === 0) return null;
  return (
    <div
      className={`identity-strip${compact ? " identity-strip-compact" : ""}`}
      data-testid="identity-strip"
    >
      {!compact && <div className="identity-strip-title">Identity</div>}
      <dl className="identity-strip-grid">
        {fields.map((f) => (
          <div className="identity-strip-item" key={f.key}>
            <dt>{f.label}</dt>
            <dd title={f.value}>{f.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function ClassificationBadge({ bundle }) {
  const cls = buildClassification(bundle);
  const tone = cls.severity
    ? FINDING_TONE[cls.severity]
    : (CONFIDENCE_COLOR[cls.confidence] || CONFIDENCE_COLOR.UNCONFIRMED);
  return (
    <div className="classification-row" data-testid="classification-badge">
      <span className="classification-label muted small">Classification</span>
      <span className="badge" style={{ background: tone }}>{cls.label}</span>
      {cls.confidence && (
        <span
          className="badge"
          style={{ background: CONFIDENCE_COLOR[cls.confidence] || CONFIDENCE_COLOR.UNCONFIRMED }}
          title="Code-owned answer confidence"
        >
          {cls.confidence}
        </span>
      )}
    </div>
  );
}

export function ExpectedVsActual({ bundle }) {
  const contrast = buildExpectedVsActual(bundle);
  return (
    <section className="story-panel expected-actual" data-testid="expected-vs-actual">
      <h4 className="story-panel-title">Expected vs Actual</h4>
      {contrast.mode === "empty" && (
        <p className="muted small">{contrast.note}</p>
      )}
      {contrast.mode === "observed_only" && (
        <>
          <p className="muted small story-honest-note">{contrast.note}</p>
          <div className="ea-grid ea-grid-single">
            <div className="ea-card ea-actual">
              <div className="ea-card-label">Observed (from logs)</div>
              <div className="ea-card-body">{contrast.actual}</div>
            </div>
          </div>
        </>
      )}
      {contrast.mode === "explicit" && (
        <div className="ea-grid">
          <div className="ea-card ea-expected">
            <div className="ea-card-label">Expected</div>
            <div className="ea-card-body">{contrast.expected || <span className="muted">—</span>}</div>
          </div>
          <div className="ea-card ea-actual">
            <div className="ea-card-label">Actual</div>
            <div className="ea-card-body">{contrast.actual || <span className="muted">—</span>}</div>
          </div>
        </div>
      )}
      {contrast.mode === "sequence_check" && (
        <>
          {contrast.sequence && (
            <p className="muted small">Sequence: <code className="inline-code">{contrast.sequence}</code></p>
          )}
          <ol className="seq-steps">
            {contrast.expected.map((s, i) => (
              <li key={i} className={`seq-step seq-${(s.status || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}>
                <span className="seq-name">{s.step}</span>
                {s.status && <span className="badge seq-status">{s.status}</span>}
                {s.timestamp && <span className="muted small">{s.timestamp}</span>}
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}

export function CitedTimeline({ bundle }) {
  const rows = buildCitedTimeline(bundle);
  return (
    <section className="story-panel cited-timeline" data-testid="cited-timeline">
      <h4 className="story-panel-title">Cited timeline</h4>
      {rows.length === 0 ? (
        <p className="muted small">No timestamped verified facts or ranked findings to cite yet.</p>
      ) : (
        <ol className="cited-timeline-list">
          {rows.map((r, i) => (
            <li key={i} className="cited-timeline-row">
              <span className="cited-ts">{r.timestamp || "—"}</span>
              <span className="cited-label">
                {r.category && <span className="verified-cat">{r.category}</span>}
                {r.label}
                {r.severity && (
                  <span className="badge" style={{ background: FINDING_TONE[r.severity] || "var(--muted)" }}>
                    {r.severity}
                  </span>
                )}
              </span>
              <span className="cited-cites">
                {r.device_label && <span className="badge device-badge">{r.device_label}</span>}
                <CaptureCite filename={r.original_filename} />
                <SourceCite source={r.source} />
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/**
 * Full story block for a diagnose/scan result.
 * Renders above VerifiedFromLogBand / NarrationBand.
 */
export default function DiagnosisStory({
  bundle,
  deviceContext,
  deviceInfo,
  capture,
  deviceLabel,
}) {
  if (!bundle) return null;
  const ctx = deviceContext || bundle.device_context || null;
  return (
    <section className="diagnosis-story" data-testid="diagnosis-story">
      <div className="diagnosis-story-head">
        <h3>Diagnosis story</h3>
        <ClassificationBadge bundle={bundle} />
      </div>
      <p className="muted small answer-band-note">
        Identity, classification, and timeline from parser/code-owned fields only — not LLM invention.
        Expected-sequence checks appear only when the bundle includes them.
      </p>
      <IdentityStrip
        deviceContext={ctx}
        deviceInfo={deviceInfo}
        capture={capture}
        deviceLabel={deviceLabel}
      />
      <ExpectedVsActual bundle={bundle} />
      <CitedTimeline bundle={bundle} />
    </section>
  );
}
