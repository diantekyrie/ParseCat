import { useEffect, useState, useCallback, useMemo, useRef } from "react";
// Dated incident ordinals do not year-wrap (Dec 31 vs Jan 1 looks ~31 days); see incidentWindow.js.
import { matchesIncidentWindow } from "./incidentWindow";

const SEVERITY_COLOR = { critical: "var(--red)", warning: "var(--amber)", info: "var(--blue)" };
const CONFIDENCE_COLOR = { HIGH: "var(--green)", MEDIUM: "var(--amber)", LOW: "var(--orange)", UNCONFIRMED: "var(--muted)" };
const TABS = [
  { id: "overview", label: "Overview" },
  { id: "connectivity", label: "Connectivity" },
  { id: "battery", label: "Battery" },
  { id: "timeline", label: "Timeline" },
];

async function api(path, opts) {
  const res = await fetch(`/api${path}`, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function searchable(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.toLowerCase();
  return JSON.stringify(value).toLowerCase();
}

function matchesQuery(value, query) {
  const q = query.trim().toLowerCase();
  return !q || searchable(value).includes(q);
}

function downloadText(filename, text, type = "text/plain") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function packageLike(row) {
  return row?.package ?? row?.executable ?? row?.uid_token ?? row?.label ?? "";
}

// The LLM report now follows a fixed markdown structure (SYSTEM_PROMPT
// rule 13: ## headings, bullet/numbered lists, **bold**, `code`). This
// renders that small, controlled subset as real elements instead of
// showing literal "##"/"**" characters in a <pre> block -- no markdown
// library, since the format the LLM is instructed to use is narrow and
// fully known ahead of time.
function renderInline(text, keyPrefix) {
  const parts = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;
  let i = 0;
  while ((match = regex.exec(text))) {
    if (match.index > lastIndex) parts.push(text.slice(lastIndex, match.index));
    const token = match[0];
    if (token.startsWith("**")) {
      parts.push(<strong key={`${keyPrefix}-${i++}`}>{token.slice(2, -2)}</strong>);
    } else {
      parts.push(<code key={`${keyPrefix}-${i++}`} className="inline-code">{token.slice(1, -1)}</code>);
    }
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex));
  return parts;
}

function renderMarkdown(text) {
  if (!text) return null;
  const lines = text.split("\n");
  const blocks = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^#{2,4}\s+/.test(line)) {
      const Tag = line.startsWith("### ") || line.startsWith("#### ") ? "h4" : "h3";
      const content = line.replace(/^#{2,4}\s+/, "");
      blocks.push(<Tag key={key} className="report-heading">{renderInline(content, key)}</Tag>);
      key += 1;
      i += 1;
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ""));
        i += 1;
      }
      blocks.push(
        <ul key={key} className="report-list">
          {items.map((it, idx) => <li key={idx}>{renderInline(it, `${key}-${idx}`)}</li>)}
        </ul>
      );
      key += 1;
      continue;
    }
    if (/^\s*\d+\.\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ""));
        i += 1;
      }
      blocks.push(
        <ol key={key} className="report-list">
          {items.map((it, idx) => <li key={idx}>{renderInline(it, `${key}-${idx}`)}</li>)}
        </ol>
      );
      key += 1;
      continue;
    }
    if (line.trim() === "") {
      i += 1;
      continue;
    }
    const paraLines = [];
    while (
      i < lines.length && lines[i].trim() !== ""
      && !/^#{2,4}\s+/.test(lines[i]) && !/^\s*[-*]\s+/.test(lines[i]) && !/^\s*\d+\.\s+/.test(lines[i])
    ) {
      paraLines.push(lines[i]);
      i += 1;
    }
    blocks.push(<p key={key} className="report-para">{renderInline(paraLines.join(" "), key)}</p>);
    key += 1;
  }
  return blocks;
}

function SourceTag({ source }) {
  if (!source) return null;
  return (
    <span className="src">
      {source.section}:{source.line_start}
      {source.line_end !== source.line_start ? `-${source.line_end}` : ""}
    </span>
  );
}

// Rows in the merged summary come from possibly-different captures (and,
// in an investigation, possibly-different physical devices) -- this makes
// which one a given row came from visible everywhere it's shown, not just
// implied by whichever capture happens to be selected in the sidebar.
function CaptureTag({ filename }) {
  if (!filename) return null;
  const short = filename.length > 30 ? `${filename.slice(0, 27)}…` : filename;
  return <span className="capture-tag" title={filename}>{short}</span>;
}

// Renders a kilobyte figure at a human scale. A null/undefined value means
// the capture did not report the field, which is a different claim from
// reporting zero -- so it shows as "unknown" rather than "0 MB".
// Seconds as a readable span for the location tables.
function formatDuration(seconds) {
  if (seconds == null) return "unknown";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s ? `${m}m ${s}s` : `${m}m`;
}

function formatKb(kb) {
  if (kb === null || kb === undefined) return "unknown";
  if (kb >= 1024 * 1024) return `${(kb / 1024 / 1024).toFixed(1)} GB`;
  return `${Math.round(kb / 1024).toLocaleString()} MB`;
}

function StatCard({ label, value, tone }) {
  return (
    <div className={`stat stat-${tone || "default"}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function DeviceInfoPanel({ info }) {
  if (!info) return <p className="muted">No device info parsed for this capture.</p>;
  const rows = [
    ["Manufacturer", info.manufacturer], ["Model", info.model],
    ["Android", info.android_release ? `Android ${info.android_release} (SDK ${info.sdk_version})` : null],
    ["Build", info.build_id], ["Security patch", info.security_patch],
    ["CPU", info.cpu_abi], ["Bootloader", info.bootloader], ["Hardware", info.hardware],
    ["Build type", info.build_type], ["Serial", info.serial],
    ["Uptime", info.uptime], ["Timezone", info.timezone],
    ["Encryption", info.crypto_state], ["Verified boot", info.verified_boot_state],
    ["Debuggable", info.debuggable === null ? null : String(info.debuggable)],
    ["Network", info.network], ["Radio", info.radio],
  ].filter(([, v]) => v);
  return (
    <div className="device-grid">
      {rows.map(([k, v]) => (
        <div className="device-row" key={k}>
          <span className="device-key">{k}</span>
          <span className="device-val">{v}</span>
        </div>
      ))}
    </div>
  );
}

function Timeline({ events }) {
  if (!events || events.length === 0) return <p className="muted">No timestamped events parsed.</p>;
  return (
    <div className="timeline">
      {events.map((e, i) => (
        <div className="timeline-row" key={i}>
          <span className="timeline-dot" style={{ background: SEVERITY_COLOR[e.severity] || "var(--muted)" }} />
          <span className="timeline-ts">{e.timestamp}</span>
          <span className="timeline-label">{e.label} <CaptureTag filename={e.original_filename} /></span>
          <SourceTag source={e.source} />
        </div>
      ))}
    </div>
  );
}

// Code-computed capture_coverage.statement from the diagnose/scan bundle.
// Template text only -- never invent a covered range in the UI.
function CoverageNotice({ coverage }) {
  if (!coverage || !coverage.statement) return null;
  const tone =
    coverage.relation === "outside" || coverage.relation === "in_gap"
      ? "coverage-gap"
      : coverage.relation === "inside"
        ? "coverage-ok"
        : "coverage-info";
  return (
    <div className={`coverage-notice ${tone}`} data-coverage-relation={coverage.relation || ""}>
      <strong>Capture coverage</strong>
      <p>{coverage.statement}</p>
    </div>
  );
}

function TriageControls({
  appFilter,
  setAppFilter,
  timelineFilter,
  setTimelineFilter,
  incidentTime,
  setIncidentTime,
  incidentWindow,
  setIncidentWindow,
  onExportSummary,
  exportSummaryDisabled,
}) {
  return (
    <section className="panel triage-panel">
      <div className="triage-head">
        <h2>Local triage controls</h2>
        <button type="button" onClick={onExportSummary} disabled={exportSummaryDisabled}>Export summary JSON</button>
      </div>
      <div className="triage-grid">
        <label>
          App / package filter
          <input
            type="text"
            placeholder="package, app, UID, executable"
            value={appFilter}
            onChange={(e) => setAppFilter(e.target.value)}
          />
        </label>
        <label>
          Timeline text filter
          <input
            type="text"
            placeholder="crash, wifi, bluetooth, reason..."
            value={timelineFilter}
            onChange={(e) => setTimelineFilter(e.target.value)}
          />
        </label>
        <label>
          Incident time
          <input
            type="time"
            value={incidentTime}
            onChange={(e) => setIncidentTime(e.target.value)}
          />
        </label>
        <label>
          Window +/- minutes
          <input
            type="number"
            min="1"
            max="240"
            value={incidentWindow}
            onChange={(e) => setIncidentWindow(Number(e.target.value) || 1)}
          />
        </label>
      </div>
    </section>
  );
}

const FINDING_TONE = { CRITICAL: "var(--red)", HIGH: "var(--orange)", MEDIUM: "var(--amber)", LOW: "var(--blue)" };

function FindingsList({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <p className="muted small">
        No crashes, ANRs, disconnects, or Bluetooth/pairing anomalies were found in the captures
        checked. That means nothing turned up in the categories ParseCat parses — not that the
        device is problem-free.
      </p>
    );
  }
  const counts = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});
  return (
    <>
      <div className="finding-tally">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
          counts[sev] ? (
            <span className="finding-count" key={sev} style={{ color: FINDING_TONE[sev] }}>
              <b>{counts[sev]}</b> {sev.toLowerCase()}
            </span>
          ) : null
        ))}
      </div>
      <ul className="finding-list">
        {findings.map((f, i) => (
          <li key={i} style={{ borderLeftColor: FINDING_TONE[f.severity] }}>
            <div className="finding-head">
              <span className="badge" style={{ background: FINDING_TONE[f.severity] }}>{f.severity}</span>
              <strong>{f.title}</strong>
              {f.occurrences > 1 && <span className="finding-occ">×{f.occurrences}</span>}
              {f.confidence && <span className="badge" style={{ background: CONFIDENCE_COLOR[f.confidence] }}>{f.confidence}</span>}
            </div>
            {f.detail && <div className="muted small finding-detail">{f.detail}</div>}
            <div className="finding-meta">
              {f.occurrences > 1 && f.first_timestamp && (
                <span className="muted small">{f.first_timestamp} → {f.last_timestamp}</span>
              )}
              {f.occurrences === 1 && f.timestamp && <span className="muted small">{f.timestamp}</span>}
              <CaptureTag filename={f.original_filename} />
              <SourceTag source={f.source} />
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}

function ClaimCard({ claim, deviceLabel }) {
  const s = claim.verified_state;
  return (
    <div className="claim-card">
      <div className="claim-header">
        <strong>{claim.package}</strong>
        {deviceLabel && <span className="badge device-badge">{deviceLabel}</span>}
        <span className="badge" style={{ background: CONFIDENCE_COLOR[claim.confidence] }}>{claim.confidence}</span>
        <span className="muted small">({claim.matched_how})</span>
      </div>
      <p className="muted small">{claim.corroboration}</p>
      <table className="fact-table">
        <tbody>
          <tr><td>Top of audio focus stack</td><td>{String(s.is_top_of_audio_focus_stack)}</td><td></td></tr>
          <tr>
            <td>MediaSession state</td>
            <td>{s.media_session_playback_state ?? "unknown"}{s.media_session_active !== null ? ` (active=${s.media_session_active})` : ""}</td>
            <td><SourceTag source={s.media_session_source} /></td>
          </tr>
          <tr>
            <td>Latest audio focus event</td>
            <td>{s.latest_focus_event ? `${s.latest_focus_event.event_type} @ ${s.latest_focus_event.timestamp}` : "none"}</td>
            <td><SourceTag source={s.latest_focus_event?.source} /></td>
          </tr>
          <tr><td>targetSdk</td><td>{s.target_sdk ?? "unknown"}</td><td><SourceTag source={s.target_sdk_source} /></td></tr>
        </tbody>
      </table>
      {claim.cross_capture_history && (
        <div className="history">
          {/* captures_checked is how many captures actually had matching evidence for this
              package -- NOT how many exist on file (captures_on_file). Showing only
              captures_checked reads as "we only looked at N," when the other
              captures_on_file - captures_checked captures were genuinely checked and
              correctly found to have nothing to report. */}
          Checked {claim.cross_capture_history.captures_checked} of{" "}
          {claim.cross_capture_history.captures_on_file} capture(s) on file
          {claim.cross_capture_history.captures_on_file > claim.cross_capture_history.captures_checked
            ? ` (${claim.cross_capture_history.captures_on_file - claim.cross_capture_history.captures_checked} had no evidence for this package)`
            : ""}
          . Ever requested audio focus:{" "}
          {String(claim.cross_capture_history.ever_requested_audio_focus)} ({claim.cross_capture_history.focus_request_count_all_captures} total).
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [devices, setDevices] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [deviceLabel, setDeviceLabel] = useState("");
  const [investigationLabel, setInvestigationLabel] = useState("");
  const [captures, setCaptures] = useState([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [uploadProgress, setUploadProgress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [askScope, setAskScope] = useState("device"); // "device" | "investigation"
  const [question, setQuestion] = useState("");
  // Keyed by capture_id rather than a single value so switching which
  // capture is selected doesn't discard a previously-run diagnosis --
  // re-running it costs real LLM tokens, and the user may just be
  // glancing at another capture's parsed facts before coming back.
  const [diagnosisByCapture, setDiagnosisByCapture] = useState({});
  const diagnosis = selectedCaptureId != null ? diagnosisByCapture[selectedCaptureId] ?? null : null;
  const [diagnosing, setDiagnosing] = useState(false);
  // Auto-scan is cached per capture for the same reason diagnoses are:
  // re-running costs real LLM tokens and the user may just be glancing at
  // another capture before coming back.
  const [scanByCapture, setScanByCapture] = useState({});
  const scan = selectedCaptureId != null ? scanByCapture[selectedCaptureId] ?? null : null;
  const [scanning, setScanning] = useState(false);
  const [followUpQuestion, setFollowUpQuestion] = useState("");
  const [followUpBusy, setFollowUpBusy] = useState(false);
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState("");
  const [invQuestion, setInvQuestion] = useState("");
  const [invDiagnosis, setInvDiagnosis] = useState(null);
  const [invDiagnosing, setInvDiagnosing] = useState(false);
  const [invFollowUpQuestion, setInvFollowUpQuestion] = useState("");
  const [invFollowUpBusy, setInvFollowUpBusy] = useState(false);
  const [appFilter, setAppFilter] = useState("");
  const [timelineFilter, setTimelineFilter] = useState("");
  const [incidentTime, setIncidentTime] = useState("");
  const [incidentWindow, setIncidentWindow] = useState(15);

  const refreshDevices = useCallback(() => {
    api("/devices").then(setDevices).catch(() => {});
  }, []);

  const refreshInvestigations = useCallback(() => {
    api("/investigations").then(setInvestigations).catch(() => {});
  }, []);

  useEffect(() => { refreshDevices(); }, [refreshDevices]);
  useEffect(() => { refreshInvestigations(); }, [refreshInvestigations]);

  useEffect(() => {
    api("/llm/providers").then((ps) => {
      setProviders(ps);
      const firstAvailable = ps.find((p) => p.available);
      if (firstAvailable) setProvider(firstAvailable.id);
    }).catch(() => {});
  }, []);

  const hasInvestigationOption = investigationLabel.trim().length > 0 && captures.length >= 2;
  // Falls back to "device" scope automatically if the investigation option
  // disappears (label cleared, or fewer than 2 linked captures) so the
  // toggle can never point at a scope that no longer has a form to show.
  useEffect(() => {
    if (!hasInvestigationOption && askScope === "investigation") setAskScope("device");
  }, [hasInvestigationOption, askScope]);

  // Every keystroke in the device-label field can fire a lookup; requests
  // don't resolve in the order they were sent (a stale, still-typing label
  // like "demo-devic" can 404 and land AFTER the final "demo-device" one
  // resolves, silently stomping the correct state with an error). Both
  // request kinds are tagged with a monotonic id and a resolved response is
  // applied only if it's still the most recent request of its kind.
  const captureLookupSeq = useRef(0);
  const summarySeq = useRef(0);

  // Fetches the merged summary (every capture in the current device or
  // investigation, parsed and combined into one dashboard payload with
  // each row tagged by which capture it came from) rather than one
  // capture's summary at a time -- this is what lets the dashboard show
  // "all logs at once" instead of requiring a click through each capture
  // to see its own facts.
  const loadMergedSummary = useCallback((path) => {
    if (!path) { setSummary(null); return; }
    const seq = ++summarySeq.current;
    api(path)
      .then((s) => {
        if (seq !== summarySeq.current) return;
        setSummary(Object.keys(s).length > 0 ? s : null);
        setError(null);
      })
      .catch((e) => {
        if (seq !== summarySeq.current) return;
        setError(String(e));
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadCaptures = useCallback((label) => {
    if (!label) { setCaptures([]); setSummary(null); return; }
    const seq = ++captureLookupSeq.current;
    api(`/devices/${encodeURIComponent(label)}/captures`)
      .then((cs) => {
        if (seq !== captureLookupSeq.current) return; // superseded by a later keystroke
        setCaptures(cs);
        setError(null);
        if (cs.length > 0) {
          setSelectedCaptureId(cs[cs.length - 1].id);
          loadMergedSummary(`/devices/${encodeURIComponent(label)}/summary`);
        } else {
          setSummary(null);
        }
      })
      .catch(() => {
        if (seq !== captureLookupSeq.current) return;
        setCaptures([]);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadInvestigationCaptures = useCallback((label) => {
    if (!label) {
      loadCaptures(deviceLabel);
      return;
    }
    const seq = ++captureLookupSeq.current;
    api(`/investigations/${encodeURIComponent(label)}/captures`)
      .then((cs) => {
        if (seq !== captureLookupSeq.current) return;
        setCaptures(cs);
        setError(null);
        if (cs.length > 0) {
          setSelectedCaptureId(cs[cs.length - 1].id);
          loadMergedSummary(`/investigations/${encodeURIComponent(label)}/summary`);
        } else {
          setSummary(null);
        }
      })
      .catch(() => {
        if (seq !== captureLookupSeq.current) return;
        setCaptures([]);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceLabel, loadCaptures]);

  // Only changes which capture the "This device" Ask button targets
  // (POST /captures/{id}/diagnose still needs one specific id) -- the
  // dashboard itself always shows the merged view for every capture
  // currently loaded, not just this one.
  function selectCapture(id) {
    setSelectedCaptureId(id);
  }

  async function handleUpload(e) {
    e.preventDefault();
    if (selectedFiles.length === 0 || !deviceLabel) return;
    setBusy(true);
    setError(null);
    setUploadProgress("");
    try {
      let latestCaptureId = null;
      for (let i = 0; i < selectedFiles.length; i += 1) {
        const uploadFile = selectedFiles[i];
        setUploadProgress(`Uploading ${i + 1}/${selectedFiles.length}: ${uploadFile.name}`);
        const form = new FormData();
        form.append("device_label", deviceLabel);
        if (investigationLabel.trim()) form.append("investigation_label", investigationLabel.trim());
        form.append("file", uploadFile);
        const data = await api("/captures", { method: "POST", body: form });
        latestCaptureId = data.capture_id;
      }
      refreshDevices();
      refreshInvestigations();
      if (investigationLabel.trim()) loadInvestigationCaptures(investigationLabel.trim());
      else loadCaptures(deviceLabel);
      if (latestCaptureId) setSelectedCaptureId(latestCaptureId);
      setSelectedFiles([]);
      setFileInputKey((key) => key + 1);
      setUploadProgress("");
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleScan() {
    if (!selectedCaptureId) return;
    const captureId = selectedCaptureId;
    setScanning(true);
    setError(null);
    try {
      const form = new FormData();
      if (provider) form.append("provider", provider);
      const data = await api(`/captures/${captureId}/scan`, { method: "POST", body: form });
      setScanByCapture((prev) => ({ ...prev, [captureId]: data }));
    } catch (err) {
      setError(String(err));
    } finally {
      setScanning(false);
    }
  }

  async function handleDiagnose(e) {
    e.preventDefault();
    if (!selectedCaptureId || !question) return;
    const captureId = selectedCaptureId;
    setDiagnosing(true);
    setError(null);
    setDiagnosisByCapture((prev) => ({ ...prev, [captureId]: null }));
    try {
      const form = new FormData();
      form.append("question", question);
      if (provider) form.append("provider", provider);
      const data = await api(`/captures/${captureId}/diagnose`, { method: "POST", body: form });
      setDiagnosisByCapture((prev) => ({ ...prev, [captureId]: data }));
      setFollowUpQuestion("");
    } catch (err) {
      setError(String(err));
    } finally {
      setDiagnosing(false);
    }
  }

  // Follow-up questions reuse this capture's fresh fact bundle (built the
  // same way as any other question -- see build_diagnosis_bundle) but tell
  // the LLM about prior turns for continuity, so "what about the other
  // one?" resolves without the user re-stating context. Prior turns are
  // never treated as evidence themselves (SYSTEM_PROMPT rule 14) -- every
  // claim in the follow-up's answer still has to trace back to this turn's
  // own verified bundle.
  async function handleFollowUp(e) {
    e.preventDefault();
    if (!selectedCaptureId || !followUpQuestion || !diagnosis) return;
    const captureId = selectedCaptureId;
    const priorTurns = [
      { question: diagnosis.bundle.question, report: diagnosis.report },
      ...(diagnosis.followUps || []),
    ];
    const askedQuestion = followUpQuestion;
    setFollowUpBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("question", askedQuestion);
      if (provider) form.append("provider", provider);
      form.append("history", JSON.stringify(priorTurns));
      const data = await api(`/captures/${captureId}/diagnose`, { method: "POST", body: form });
      setDiagnosisByCapture((prev) => {
        const existing = prev[captureId];
        if (!existing) return prev; // the base diagnosis was cleared while this was in flight
        return {
          ...prev,
          [captureId]: {
            ...existing,
            followUps: [
              ...(existing.followUps || []),
              { question: askedQuestion, report: data.report, llm_error: data.llm_error,
                provider: data.provider, bundle: data.bundle },
            ],
          },
        };
      });
      setFollowUpQuestion("");
    } catch (err) {
      setError(String(err));
    } finally {
      setFollowUpBusy(false);
    }
  }

  async function handleDiagnoseInvestigation(e) {
    e.preventDefault();
    if (!investigationLabel.trim() || !invQuestion) return;
    setInvDiagnosing(true);
    setError(null);
    setInvDiagnosis(null);
    try {
      const form = new FormData();
      form.append("question", invQuestion);
      if (provider) form.append("provider", provider);
      const data = await api(
        `/investigations/${encodeURIComponent(investigationLabel.trim())}/diagnose`,
        { method: "POST", body: form },
      );
      setInvDiagnosis(data);
      setInvFollowUpQuestion("");
    } catch (err) {
      setError(String(err));
    } finally {
      setInvDiagnosing(false);
    }
  }

  async function handleInvFollowUp(e) {
    e.preventDefault();
    if (!investigationLabel.trim() || !invFollowUpQuestion || !invDiagnosis) return;
    const label = investigationLabel.trim();
    const priorTurns = [
      { question: invDiagnosis.bundle.question, report: invDiagnosis.report },
      ...(invDiagnosis.followUps || []),
    ];
    const askedQuestion = invFollowUpQuestion;
    setInvFollowUpBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("question", askedQuestion);
      if (provider) form.append("provider", provider);
      form.append("history", JSON.stringify(priorTurns));
      const data = await api(`/investigations/${encodeURIComponent(label)}/diagnose`, { method: "POST", body: form });
      setInvDiagnosis((existing) => (existing ? {
        ...existing,
        followUps: [
          ...(existing.followUps || []),
          { question: askedQuestion, report: data.report, llm_error: data.llm_error,
            provider: data.provider, bundle: data.bundle },
        ],
      } : existing));
      setInvFollowUpQuestion("");
    } catch (err) {
      setError(String(err));
    } finally {
      setInvFollowUpBusy(false);
    }
  }

  function exportInvestigationDiagnosis() {
    if (!invDiagnosis) return;
    const followUpText = (invDiagnosis.followUps || []).map((turn, i) => [
      "",
      `follow-up ${i + 1}: ${turn.question}`,
      turn.report || `LLM narration failed: ${turn.llm_error}`,
    ].join("\n")).join("\n");
    const report = [
      "ParseCat investigation diagnosis export",
      `investigation: ${investigationLabel}`,
      `captures: ${invDiagnosis.bundle.captures.map((c) => `#${c.capture_id} (${c.device_label})`).join(", ")}`,
      `provider: ${invDiagnosis.provider || "auto"}`,
      "",
      "question:",
      invDiagnosis.bundle.question,
      "",
      "report:",
      invDiagnosis.report || `LLM narration failed: ${invDiagnosis.llm_error}`,
      followUpText,
      "",
      "verified fact bundle (all captures):",
      JSON.stringify(invDiagnosis.bundle, null, 2),
    ].join("\n");
    downloadText(`parsecat-investigation-${investigationLabel}-diagnosis.txt`, report);
  }

  const c = summary?.counts;
  const filtered = useMemo(() => {
    if (!summary) return null;
    const appMatches = (row) => matchesQuery(packageLike(row), appFilter) || matchesQuery(row, appFilter);
    const timeMatches = (row) => matchesIncidentWindow(row.timestamp, incidentTime, incidentWindow);
    return {
      crash_events: summary.crash_events.filter((row) => appMatches(row) && timeMatches(row)),
      anrs: summary.anrs.filter((row) => appMatches(row) && timeMatches(row)),
      tombstones: summary.tombstones.filter((row) => appMatches(row) && timeMatches(row)),
      top_battery_consumers: summary.top_battery_consumers.filter(appMatches),
      wifi_events: summary.wifi_events.filter((row) => matchesQuery(row, appFilter) && timeMatches(row)),
      selinux_denials: (summary.selinux_denials || []).filter((row) => appMatches(row) && timeMatches(row)),
      process_kills: (summary.process_kills || []).filter((row) => appMatches(row) && timeMatches(row)),
      gnss_degraded_spans: summary.gnss_degraded_spans || [],
      top_freeze_offenders: summary.top_freeze_offenders.filter(appMatches),
      media_sessions: summary.media_sessions.filter(appMatches),
      timeline: summary.timeline.filter((row) => (
        matchesQuery(row, timelineFilter)
        && matchesQuery(row, appFilter)
        && matchesIncidentWindow(row.timestamp, incidentTime, incidentWindow)
      )),
    };
  }, [summary, appFilter, timelineFilter, incidentTime, incidentWindow]);

  const summaryScopeSlug = (investigationLabel.trim() || deviceLabel || "capture").replace(/[^\w-]+/g, "_");

  function exportSummary() {
    if (!summary) return;
    downloadText(
      `parsecat-${summaryScopeSlug}-summary.json`,
      JSON.stringify(summary, null, 2),
      "application/json",
    );
  }

  function exportDiagnosis() {
    if (!diagnosis || !selectedCaptureId) return;
    const targetCapture = captures.find((cap) => cap.id === selectedCaptureId);
    const followUpText = (diagnosis.followUps || []).map((turn, i) => [
      "",
      `follow-up ${i + 1}: ${turn.question}`,
      turn.report || `LLM narration failed: ${turn.llm_error}`,
    ].join("\n")).join("\n");
    const report = [
      "ParseCat diagnosis export",
      `capture: #${selectedCaptureId}${targetCapture ? ` ${targetCapture.original_filename}` : ""}`,
      `provider: ${diagnosis.provider || "auto"}`,
      "",
      "question:",
      diagnosis.bundle.question,
      "",
      "report:",
      diagnosis.report || `LLM narration failed: ${diagnosis.llm_error}`,
      followUpText,
      "",
      "verified fact bundle:",
      JSON.stringify(diagnosis.bundle, null, 2),
    ].join("\n");
    downloadText(`parsecat-capture-${selectedCaptureId}-diagnosis.txt`, report);
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">ParseCat</div>
        <div className="tagline">Device log diagnosis, backed by parsed facts, not vibes.</div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <section className="panel">
            <h2>Device</h2>
            <label>
              Device identifier
              <input
                type="text" list="known-devices" placeholder="e.g. frankel-pixel"
                value={deviceLabel}
                onChange={(e) => {
                  setDeviceLabel(e.target.value);
                  if (!investigationLabel) loadCaptures(e.target.value);
                }}
              />
              <datalist id="known-devices">
                {devices.map((d) => <option key={d.id} value={d.label} />)}
              </datalist>
            </label>
            <label>
              Bug folder
              <input
                type="text" list="known-investigations" placeholder="e.g. wifi-drop-at-hotel"
                value={investigationLabel}
                onChange={(e) => {
                  setInvestigationLabel(e.target.value);
                  setInvDiagnosis(null);
                  loadInvestigationCaptures(e.target.value);
                }}
              />
              <datalist id="known-investigations">
                {investigations.map((i) => <option key={i.id} value={i.label} />)}
              </datalist>
            </label>
            <label>
              Capture files
              <input
                key={fileInputKey}
                type="file"
                accept=".zip,.txt,.pcap,.pcapng"
                multiple
                onChange={(e) => setSelectedFiles(Array.from(e.target.files || []))}
              />
            </label>
            {selectedFiles.length > 0 && (
              <p className="muted small">{selectedFiles.length} file(s) selected.</p>
            )}
            {uploadProgress && <p className="muted small">{uploadProgress}</p>}
            <button onClick={handleUpload} disabled={busy || selectedFiles.length === 0 || !deviceLabel}>
              {busy ? "Parsing..." : selectedFiles.length > 1 ? "Upload & parse all" : "Upload & parse"}
            </button>
          </section>

          <section className="panel">
            <h2>Captures for this device</h2>
            {captures.length === 0 && <p className="muted small">None yet.</p>}
            <ul className="capture-list">
              {captures.map((cap) => (
                <li
                  key={cap.id}
                  className={[
                    cap.id === selectedCaptureId ? "active" : "",
                    cap.severity?.has_findings ? "has-findings" : "",
                  ].filter(Boolean).join(" ")}
                  onClick={() => selectCapture(cap.id)}
                >
                  <div className="cap-name">
                    {cap.severity?.has_findings && (
                      <span
                        className="sev-dot"
                        title={`${cap.severity.java_crashes} crash(es), ${cap.severity.anrs} ANR(s), ${cap.severity.wifi_disconnects} Wi-Fi disconnect(s)`}
                      />
                    )}
                    #{cap.id} {cap.original_filename}
                  </div>
                  <div className="cap-date muted small">{cap.ingested_at}</div>
                </li>
              ))}
            </ul>
          </section>
        </aside>

        <main className="main">
          {error && <div className="error">{error}</div>}

          <section className="panel ask-hero">
            <div className="ask-hero-head">
              <h2>Ask</h2>
              {hasInvestigationOption && (
                <div className="scope-toggle">
                  <button type="button" className={askScope === "device" ? "active" : ""} onClick={() => setAskScope("device")}>
                    This device
                  </button>
                  <button type="button" className={askScope === "investigation" ? "active" : ""} onClick={() => setAskScope("investigation")}>
                    Investigation &ldquo;{investigationLabel.trim()}&rdquo;
                  </button>
                </div>
              )}
            </div>

            {askScope === "device" && summary && c && (
              <div className="severity-strip">
                <StatCard label="Java crashes" value={c.java_crashes} tone={c.java_crashes > 0 ? "critical" : "ok"} />
                <StatCard label="Native crashes" value={c.native_crashes} tone={c.native_crashes > 0 ? "warning" : "ok"} />
                <StatCard label="ANRs" value={c.anrs} tone={c.anrs > 0 ? "critical" : "ok"} />
                <StatCard label="Wi-Fi disconnects" value={c.wifi_disconnections} tone={c.wifi_disconnections > 0 ? "warning" : "ok"} />
                <StatCard label="SELinux blocked" value={c.selinux_enforced_denials ?? 0} tone={(c.selinux_enforced_denials ?? 0) > 0 ? "warning" : "ok"} />
                <StatCard label="Processes killed" value={c.process_kills ?? 0} tone={(c.process_kills ?? 0) > 0 ? "warning" : "ok"} />
              </div>
            )}

            {askScope === "device" ? (
              <>
                <div className="scan-row">
                  <button type="button" onClick={handleScan} disabled={scanning || !selectedCaptureId}>
                    {scanning ? "Scanning…" : "Scan for problems"}
                  </button>
                  <span className="muted small">
                    No question needed — checks every evidence category and ranks what it finds by severity.
                  </span>
                </div>

                {scan && (
                  <div className="ask-result">
                    <CoverageNotice coverage={scan.bundle.capture_coverage} />
                    <h3>Scan findings</h3>
                    <FindingsList findings={scan.bundle.ranked_findings} />
                    {scan.report ? (
                      <>
                        <h3>Summary {scan.provider && <span className="muted small"> - narrated by {providers.find((p) => p.id === scan.provider)?.label || scan.provider}</span>}</h3>
                        <div className="report">{renderMarkdown(scan.report)}</div>
                      </>
                    ) : (
                      <div className="error">LLM narration failed (findings above are unaffected): {scan.llm_error}</div>
                    )}
                  </div>
                )}

                <p className="muted small">
                  Named apps are independently verified against parsed facts; the question's framing is not taken as
                  fact. Device-wide evidence (crashes, Wi-Fi, battery, pairing) is checked across every capture on
                  file for this device, not just the one selected.
                </p>
                <form onSubmit={handleDiagnose}>
                  <textarea
                    rows={3}
                    placeholder="e.g. Was there a crash on this device? Did com.apple.android.music hold audio focus?"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                  />
                  <div className="ask-row">
                    <label className="inline-label">
                      Narrated by
                      <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                        {providers.map((p) => (
                          <option key={p.id} value={p.id} disabled={!p.available}>
                            {p.label}{!p.available ? " (no key set)" : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="submit" disabled={diagnosing || !question || !selectedCaptureId}>
                      {diagnosing ? "Diagnosing…" : "Diagnose this device"}
                    </button>
                  </div>
                  {!selectedCaptureId && <p className="muted small">Upload or select a capture first.</p>}
                </form>

                {diagnosis && (
                  <div className="ask-result">
                    <CoverageNotice coverage={diagnosis.bundle.capture_coverage} />
                    {diagnosis.bundle.claims.length === 0 && (
                      <p className="muted">No app named in the question matched a known package — nothing to verify.</p>
                    )}
                    {diagnosis.bundle.claims.map((cl) => <ClaimCard key={cl.package} claim={cl} />)}
                    <h3>Report {diagnosis.provider && <span className="muted small"> - narrated by {providers.find((p) => p.id === diagnosis.provider)?.label || diagnosis.provider}</span>}</h3>
                    <button type="button" className="secondary-btn" onClick={exportDiagnosis}>Export diagnosis</button>
                    {diagnosis.report ? (
                      <div className="report">{renderMarkdown(diagnosis.report)}</div>
                    ) : (
                      <div className="error">LLM narration failed (facts above are unaffected): {diagnosis.llm_error}</div>
                    )}

                    {(diagnosis.followUps || []).map((turn, i) => (
                      <div className="follow-up-turn" key={i}>
                        <h3>Follow-up: {turn.question}</h3>
                        <CoverageNotice coverage={turn.bundle && turn.bundle.capture_coverage} />
                        {turn.report ? (
                          <div className="report">{renderMarkdown(turn.report)}</div>
                        ) : (
                          <div className="error">LLM narration failed: {turn.llm_error}</div>
                        )}
                      </div>
                    ))}

                    {diagnosis.report && (
                      <form onSubmit={handleFollowUp} className="follow-up-form">
                        <label>
                          Follow-up question
                          <input
                            type="text"
                            placeholder="e.g. Should I be worried about that?"
                            value={followUpQuestion}
                            onChange={(e) => setFollowUpQuestion(e.target.value)}
                          />
                        </label>
                        <button type="submit" disabled={followUpBusy || !followUpQuestion}>
                          {followUpBusy ? "Asking…" : "Ask follow-up"}
                        </button>
                      </form>
                    )}
                  </div>
                )}
              </>
            ) : (
              <>
                <p className="muted small">
                  {captures.length} capture(s) linked: {captures.map((cap) => cap.original_filename).join(", ")}. Facts
                  from every linked capture are merged and each fact is tagged with the device/file it came from —
                  this is how you correlate two physical devices in the same investigation (e.g. a phone and a watch
                  that were pairing with each other).
                </p>
                <form onSubmit={handleDiagnoseInvestigation}>
                  <textarea
                    rows={3}
                    placeholder="e.g. A network error was seen on one of these 2 devices while attempting to pair"
                    value={invQuestion}
                    onChange={(e) => setInvQuestion(e.target.value)}
                  />
                  <div className="ask-row">
                    <label className="inline-label">
                      Narrated by
                      <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                        {providers.map((p) => (
                          <option key={p.id} value={p.id} disabled={!p.available}>
                            {p.label}{!p.available ? " (no key set)" : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="submit" disabled={invDiagnosing || !invQuestion || captures.length < 2}>
                      {invDiagnosing ? "Diagnosing…" : "Diagnose across investigation"}
                    </button>
                  </div>
                </form>

                {invDiagnosis && (
                  <div className="ask-result">
                    {(invDiagnosis.bundle.captures || []).map((cap) => (
                      <CoverageNotice key={`cov-${cap.capture_id}`} coverage={cap.capture_coverage} />
                    ))}
                    {invDiagnosis.bundle.captures.map((cap) => (
                      <div key={cap.capture_id}>
                        {cap.claims.map((cl) => (
                          <ClaimCard key={`${cap.capture_id}-${cl.package}`} claim={cl} deviceLabel={cap.device_label} />
                        ))}
                      </div>
                    ))}
                    {invDiagnosis.bundle.captures.every((cap) => cap.claims.length === 0) && (
                      <p className="muted">No app named in the question matched a known package in any linked capture — nothing to verify.</p>
                    )}
                    <h3>
                      Report
                      {invDiagnosis.provider && (
                        <span className="muted small"> - narrated by {providers.find((p) => p.id === invDiagnosis.provider)?.label || invDiagnosis.provider}</span>
                      )}
                    </h3>
                    <button type="button" className="secondary-btn" onClick={exportInvestigationDiagnosis}>Export diagnosis</button>
                    {invDiagnosis.report ? (
                      <div className="report">{renderMarkdown(invDiagnosis.report)}</div>
                    ) : (
                      <div className="error">LLM narration failed (facts above are unaffected): {invDiagnosis.llm_error}</div>
                    )}

                    {(invDiagnosis.followUps || []).map((turn, i) => (
                      <div className="follow-up-turn" key={i}>
                        <h3>Follow-up: {turn.question}</h3>
                        <CoverageNotice coverage={turn.bundle && turn.bundle.capture_coverage} />
                        {turn.report ? (
                          <div className="report">{renderMarkdown(turn.report)}</div>
                        ) : (
                          <div className="error">LLM narration failed: {turn.llm_error}</div>
                        )}
                      </div>
                    ))}

                    {invDiagnosis.report && (
                      <form onSubmit={handleInvFollowUp} className="follow-up-form">
                        <label>
                          Follow-up question
                          <input
                            type="text"
                            placeholder="e.g. Which device should I focus on fixing first?"
                            value={invFollowUpQuestion}
                            onChange={(e) => setInvFollowUpQuestion(e.target.value)}
                          />
                        </label>
                        <button type="submit" disabled={invFollowUpBusy || !invFollowUpQuestion}>
                          {invFollowUpBusy ? "Asking…" : "Ask follow-up"}
                        </button>
                      </form>
                    )}
                  </div>
                )}
              </>
            )}
          </section>

          {!summary && <div className="panel"><p className="muted">Upload a bugreport or pick a capture to see parsed facts.</p></div>}

          {summary && (
            <>
              <TriageControls
                appFilter={appFilter}
                setAppFilter={setAppFilter}
                timelineFilter={timelineFilter}
                setTimelineFilter={setTimelineFilter}
                incidentTime={incidentTime}
                setIncidentTime={setIncidentTime}
                incidentWindow={incidentWindow}
                setIncidentWindow={setIncidentWindow}
                onExportSummary={exportSummary}
                exportSummaryDisabled={!summary}
              />

              <div className="tabbar">
                {TABS.map((t) => (
                  <button
                    type="button" key={t.id}
                    className={`tab ${activeTab === t.id ? "active" : ""}`}
                    onClick={() => setActiveTab(t.id)}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              {activeTab === "overview" && (
                <>
                  <section className="panel">
                    <h2>Device information</h2>
                    {summary.device_infos.length === 0 && <p className="muted">No device info parsed for any linked capture.</p>}
                    {summary.device_infos.map((info) => (
                      <div key={info.capture_id} className="device-info-block">
                        <CaptureTag filename={info.original_filename} />
                        <DeviceInfoPanel info={info} />
                      </div>
                    ))}
                  </section>

                  <section className="panel">
                    <h2>Parsed facts ({summary.capture_count} capture{summary.capture_count === 1 ? "" : "s"} merged)</h2>
                    <p className="muted small">
                      {summary.captures.map((cap) => cap.original_filename).join(", ")}
                    </p>
                    {summary.parse_warnings.length > 0 && (
                      <ul className="warnings">{summary.parse_warnings.map((w) => <li key={w}>⚠ {w}</li>)}</ul>
                    )}
                    <div className="stat-grid">
                      <StatCard label="Java crashes" value={c.java_crashes} tone={c.java_crashes > 0 ? "critical" : "ok"} />
                      <StatCard label="Native crashes (tombstones)" value={c.native_crashes} tone={c.native_crashes > 0 ? "warning" : "ok"} />
                      <StatCard label="ANRs" value={c.anrs} tone={c.anrs > 0 ? "critical" : "ok"} />
                      <StatCard label="Wi-Fi disconnections" value={c.wifi_disconnections} tone="default" />
                      <StatCard label="SELinux denials" value={c.selinux_denials ?? 0} tone={(c.selinux_enforced_denials ?? 0) > 0 ? "warning" : "default"} />
                      <StatCard label="Processes killed" value={c.process_kills ?? 0} tone={(c.process_kills ?? 0) > 0 ? "warning" : "default"} />
                      <StatCard
                        label="Kernel errors (err+)"
                        value={c.kernel_err_events ?? 0}
                        tone={(c.kernel_err_events ?? 0) > 0 ? "warning" : "default"}
                      />
                      <StatCard
                        label="Thermal status"
                        value={summary.thermal_status ?? "n/a"}
                        tone={
                          summary.thermal_status && summary.thermal_status !== "none"
                            ? "warning"
                            : "default"
                        }
                      />
                      <StatCard label="Freeze events" value={c.freeze_events} tone="default" />
                      <StatCard label="Unfreeze events" value={c.unfreeze_events} tone="default" />
                      <StatCard label="Packages" value={c.packages} tone="default" />
                      <StatCard label="Foreground services" value={c.foreground_services} tone="default" />
                      <StatCard label="Media sessions" value={c.media_sessions} tone="default" />
                      <StatCard label="Focus stack entries" value={c.focus_stack_entries} tone="default" />
                    </div>
                  </section>

                  {filtered.crash_events.length > 0 && (
                    <section className="panel">
                      <h2>Java crashes</h2>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Package</th><th>Exception</th><th>Message</th><th>Root cause</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.crash_events.map((cr, i) => (
                            <tr key={i}>
                              <td>{cr.timestamp}</td><td>{cr.package}</td><td>{cr.exception_class}</td>
                              <td className="small">{cr.message}</td>
                              <td className="small">
                                {cr.root_cause_class ? (
                                  <>
                                    <strong>{cr.root_cause_class}</strong>{cr.root_cause_message ? `: ${cr.root_cause_message}` : ""}
                                    {cr.root_cause_frame && <div className="muted">{cr.root_cause_frame}</div>}
                                  </>
                                ) : <span className="muted">none</span>}
                              </td>
                              <td><CaptureTag filename={cr.original_filename} /></td>
                              <td><SourceTag source={cr.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {filtered.anrs.length > 0 && (
                    <section className="panel">
                      <h2>ANRs</h2>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Package</th><th>Reason</th><th>PID</th><th>Capture</th></tr></thead>
                        <tbody>
                          {filtered.anrs.map((a, i) => (
                            <tr key={i}>
                              <td>{a.timestamp}</td><td>{a.package ?? <span className="muted">unattributed</span>}</td>
                              <td className="small">{a.reason}</td><td>{a.pid}</td>
                              <td><CaptureTag filename={a.original_filename} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {filtered.tombstones.length > 0 && (
                    <section className="panel">
                      <h2>Native crashes (tombstones)</h2>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Package / executable</th><th>Signal</th><th>Top frame</th><th>Capture</th></tr></thead>
                        <tbody>
                          {filtered.tombstones.map((t, i) => (
                            <tr key={i}>
                              <td className="small">{t.timestamp ?? t.modified_at}</td>
                              <td>{t.package ?? <span className="muted">{t.executable ?? "unattributed"}</span>}</td>
                              <td>{t.signal_name}{t.signal_code ? ` (${t.signal_code})` : ""}</td>
                              <td className="small">{t.top_frame}</td>
                              <td><CaptureTag filename={t.original_filename} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {(summary.location_snapshot || filtered.gnss_degraded_spans.length > 0) && (
                    <section className="panel">
                      <h2>Location &amp; GPS</h2>
                      <p className="muted small">
                        Two different things, and the difference matters. <strong>Reception quality</strong> below is
                        Android&apos;s own good/poor classification, thresholded on satellite signal strength —
                        it says how well the phone could hear satellites, <em>not</em> whether any app got a wrong
                        position. Bugreports never record the coordinates delivered to an app. Weak reception
                        indoors, underground, or between tall buildings is expected physics, not a fault.
                      </p>
                      {summary.location_snapshot && (
                        <div className="stat-row">
                          <StatCard
                            label="Location services"
                            value={summary.location_snapshot.location_enabled === false ? "off" : "on"}
                            tone={summary.location_snapshot.location_enabled === false ? "warning" : "ok"}
                          />
                          <StatCard
                            label="Avg position accuracy"
                            value={
                              summary.location_snapshot.accuracy_mean_m == null
                                ? "unknown"
                                : `${summary.location_snapshot.accuracy_mean_m.toFixed(1)} m`
                            }
                          />
                          <StatCard
                            label="Weak-signal time"
                            value={
                              summary.location_snapshot.cn0_time_below_threshold_min == null
                                ? "unknown"
                                : `${summary.location_snapshot.cn0_time_below_threshold_min.toFixed(1)} min`
                            }
                            tone={
                              (summary.location_snapshot.cn0_time_below_threshold_min ?? 0) > 0
                                ? "warning"
                                : "ok"
                            }
                          />
                          <StatCard
                            label="Degraded spans"
                            value={filtered.gnss_degraded_spans.length}
                            tone={filtered.gnss_degraded_spans.length > 0 ? "warning" : "ok"}
                          />
                        </div>
                      )}
                      {summary.location_snapshot && (
                        <p className="muted small">
                          Figures above are aggregates since the device last booted — they cannot be pinned to any
                          one hour. Signal is classified good above{" "}
                          {summary.location_snapshot.cn0_threshold_dbhz ?? "?"} dB-Hz and poor below it.
                          {summary.location_snapshot.constellations
                            ? ` Constellations used in fixes: ${summary.location_snapshot.constellations}.`
                            : ""}
                        </p>
                      )}

                      {filtered.gnss_degraded_spans.length > 0 && (
                        <>
                          <h3 className="small">When reception was weak</h3>
                          <table className="fact-table">
                            <thead>
                              <tr><th>From</th><th>To</th><th>Duration</th><th>Apps holding GPS (uid)</th><th>Cite</th></tr>
                            </thead>
                            <tbody>
                              {filtered.gnss_degraded_spans.map((g, i) => (
                                <tr key={i}>
                                  <td className="small">{g.start_timestamp}</td>
                                  <td className="small">{g.end_timestamp}</td>
                                  <td className={g.duration_sec >= 300 ? "warn-text" : ""}>
                                    {formatDuration(g.duration_sec)}
                                  </td>
                                  <td className="small">
                                    {g.active_uids || <span className="muted">none recorded</span>}
                                  </td>
                                  <td><SourceTag source={g.source} /></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}

                      {summary.location_snapshot && summary.location_snapshot.app_usage.length > 0 && (
                        <>
                          <h3 className="small">Location use by app</h3>
                          <p className="muted small">
                            <strong>Delivered</strong> is how many fixes the app actually received. An app asking for
                            one per second that received far fewer was not served at the rate it requested — a fact
                            about delivery, not proof the positions were wrong.
                          </p>
                          <table className="fact-table">
                            <thead>
                              <tr><th>App</th><th>Provider</th><th>Requested</th><th>Foreground</th><th>Delivered</th></tr>
                            </thead>
                            <tbody>
                              {summary.location_snapshot.app_usage.slice(0, 12).map((u, i) => (
                                <tr key={i}>
                                  <td className="small">{u.package}</td>
                                  <td className="small">{u.provider}</td>
                                  <td className="small">{u.min_interval}/{u.max_interval}</td>
                                  <td className="small">{u.foreground_duration}</td>
                                  <td>{u.locations.toLocaleString()}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                    </section>
                  )}

                  {summary.memory_snapshot && (
                    <section className="panel">
                      <h2>Memory</h2>
                      <p className="muted small">
                        A point-in-time snapshot from <code>dumpsys meminfo</code>. <strong>Status</strong> is the
                        device&apos;s own assessment — trust it over the raw numbers. Free RAM already counts cached
                        memory as free, because cached pages are reclaimable on demand, so a small &ldquo;truly
                        free&rdquo; figure next to a large cache is normal and is <em>not</em> memory pressure.
                      </p>
                      <div className="stat-row">
                        <StatCard label="Total RAM" value={formatKb(summary.memory_snapshot.total_ram_kb)} />
                        <StatCard label="Free RAM" value={formatKb(summary.memory_snapshot.free_ram_kb)} />
                        <StatCard label="Used RAM" value={formatKb(summary.memory_snapshot.used_ram_kb)} />
                        <StatCard
                          label="Status"
                          value={summary.memory_snapshot.status ?? "not reported"}
                          tone={
                            !summary.memory_snapshot.status || summary.memory_snapshot.status === "normal"
                              ? "ok"
                              : "warning"
                          }
                        />
                      </div>
                      <p className="muted small">
                        Of that free RAM, {formatKb(summary.memory_snapshot.cached_pss_kb)} is reclaimable cached
                        memory and {formatKb(summary.memory_snapshot.truly_free_kb)} is genuinely unused.
                        {summary.memory_snapshot.zram_in_swap_kb
                          ? ` ${formatKb(summary.memory_snapshot.zram_in_swap_kb)} is compressed into ${formatKb(
                              summary.memory_snapshot.zram_physical_kb,
                            )} of ZRAM — compressed, not lost.`
                          : ""}
                      </p>
                      {summary.memory_snapshot.top_by_pss.length > 0 && (
                        <>
                          <h3 className="small">Top processes by PSS</h3>
                          <p className="muted small">
                            PSS divides shared pages by how many processes share them, so these figures can be
                            meaningfully compared between processes. (RSS, shown by <code>am_pss</code> samples
                            elsewhere, counts every resident page including shared ones — never sum RSS across
                            processes, and never compare an RSS figure to a PSS one.)
                          </p>
                          <table className="fact-table">
                            <thead>
                              <tr><th>#</th><th>Process</th><th>PID</th><th>PSS</th><th>In swap</th><th>State</th><th>Cite</th></tr>
                            </thead>
                            <tbody>
                              {summary.memory_snapshot.top_by_pss.slice(0, 10).map((u) => (
                                <tr key={`pss-${u.rank}`}>
                                  <td>{u.rank}</td>
                                  <td className="small">{u.process}</td>
                                  <td>{u.pid}</td>
                                  <td>{formatKb(u.memory_kb)}</td>
                                  <td>{u.swap_kb ? formatKb(u.swap_kb) : ""}</td>
                                  <td className="small">{u.state ?? ""}</td>
                                  <td><SourceTag source={summary.memory_snapshot.source} /></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                    </section>
                  )}

                  {filtered.process_kills.length > 0 && (
                    <section className="panel">
                      <h2>Process kills &amp; deaths</h2>
                      <p className="muted small">
                        <strong>Killed</strong> means the system deliberately ended the process and recorded a reason.
                        <strong> Died</strong> only records that the process went away — it does not by itself mean the
                        system killed it. Processes being killed is normal Android memory management; the reason and
                        OOM adjustment are what make one worth looking at.
                      </p>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Event</th><th>Process</th><th>Reason</th><th>OOM adj</th><th>RSS (kB)</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.process_kills.map((k, i) => (
                            <tr key={i}>
                              <td className="small">{k.timestamp}</td>
                              <td className={k.kind === "kill" ? "warn-text" : ""}>{k.kind === "kill" ? "killed" : "died"}</td>
                              <td className="small">{k.process}</td>
                              <td className="small">{k.reason ?? <span className="muted">not recorded</span>}</td>
                              <td>{k.oom_adj ?? ""}</td>
                              <td>{k.rss_kb || ""}</td>
                              <td><CaptureTag filename={k.original_filename} /></td>
                              <td><SourceTag source={k.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {filtered.selinux_denials.length > 0 && (
                    <section className="panel">
                      <h2>SELinux denials</h2>
                      <p className="muted small">
                        <strong>Blocked</strong> means the operation was actually refused (permissive=0) — a real
                        failure. <strong>Permissive</strong> means it was logged but allowed through, a warning about
                        what would break under enforcement, not a current failure.
                      </p>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>Effect</th><th>Permission</th><th>Domain → target</th><th>Process / app</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.selinux_denials.map((d, i) => (
                            <tr key={i}>
                              <td className="small">{d.timestamp}</td>
                              <td className={d.enforcing ? "warn-text" : ""}>
                                {d.enforcing === true ? "blocked" : d.enforcing === false ? "permissive" : "unknown"}
                              </td>
                              <td className="small">{d.permissions}</td>
                              <td className="small">{d.source_domain} → {d.target_type} ({d.target_class})</td>
                              <td className="small">{d.app || d.comm || ""}</td>
                              <td><CaptureTag filename={d.original_filename} /></td>
                              <td><SourceTag source={d.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {filtered.top_freeze_offenders.length > 0 && (
                    <section className="panel">
                      <h2>Top freeze/unfreeze offenders</h2>
                      <table className="fact-table">
                        <thead><tr><th>Package</th><th>Freezes</th><th>Unfreezes</th></tr></thead>
                        <tbody>
                          {filtered.top_freeze_offenders.map((o) => (
                            <tr key={o.package}><td>{o.package}</td><td>{o.freezes}</td><td>{o.unfreezes}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}
                </>
              )}

              {activeTab === "connectivity" && (
                <>
                  {summary.bt_hci_summary.map((bt) => (
                    <section className="panel" key={bt.capture_id}>
                      <h2>Bluetooth HCI log <CaptureTag filename={bt.original_filename} /></h2>
                      <div className="stat-grid">
                        <StatCard label="Total packets" value={bt.total_packets} tone="default" />
                        <StatCard label="Commands" value={bt.command_count} tone="default" />
                        <StatCard label="Events" value={bt.event_count} tone="default" />
                        <StatCard label="ACL data" value={bt.acl_data_count} tone="default" />
                      </div>
                      <p className="muted small">{bt.first_timestamp} &ndash; {bt.last_timestamp}</p>
                      {bt.notable_events.length > 0 && (
                        <>
                          <h3>Notable events (disconnects &amp; non-success statuses)</h3>
                          <table className="fact-table">
                            <thead><tr><th>Time</th><th>Kind</th><th>Status</th><th>Reason</th><th>Handle</th></tr></thead>
                            <tbody>
                              {bt.notable_events.map((e, i) => (
                                <tr key={i}>
                                  <td className="small">{e.timestamp}</td><td>{e.kind.replace(/_/g, " ")}</td>
                                  <td className={e.status_name !== "Success" ? "warn-text" : ""}>{e.status_name}</td>
                                  <td>{e.reason_name ?? ""}</td><td>{e.handle ?? ""}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                    </section>
                  ))}

                  {filtered.wifi_events.filter((w) => w.kind === "disconnection").length > 0 && (
                    <section className="panel">
                      <h2>Wi-Fi disconnections</h2>
                      <table className="fact-table">
                        <thead><tr><th>Time</th><th>SSID</th><th>Reason</th><th>Locally initiated</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.wifi_events.filter((w) => w.kind === "disconnection").map((w, i) => (
                            <tr key={i}>
                              <td className="small">{w.timestamp}</td><td>{w.ssid}</td>
                              <td className={!w.locally_generated ? "warn-text" : ""}>{w.reason_name}</td>
                              <td>{String(w.locally_generated)}</td>
                              <td><CaptureTag filename={w.original_filename} /></td>
                              <td><SourceTag source={w.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  )}

                  {summary.packet_capture_summary.map((p) => (
                    <section className="panel" key={p.capture_id}>
                      <h2>Packet capture <CaptureTag filename={p.original_filename} /></h2>
                      <div className="stat-grid">
                        <StatCard label="Format" value={p.format.toUpperCase()} tone="default" />
                        <StatCard label="Packets" value={p.total_packets} tone="default" />
                        <StatCard label="Captured bytes" value={p.captured_bytes} tone="default" />
                        <StatCard label="Truncated packets" value={p.truncated_packets} tone={p.truncated_packets > 0 ? "warning" : "ok"} />
                        <StatCard label="Malformed records" value={p.malformed_packets} tone={p.malformed_packets > 0 ? "critical" : "ok"} />
                      </div>
                      <p className="muted small">
                        {p.linktype_name} ({p.linktype})
                        {p.first_timestamp && p.last_timestamp ? ` | ${p.first_timestamp} - ${p.last_timestamp}` : ""}
                      </p>
                    </section>
                  ))}

                  {summary.packet_analysis.map((pa) => (
                    <section className="panel" key={pa.capture_id}>
                      <h2>Packet protocol analysis <CaptureTag filename={pa.original_filename} /></h2>
                      <p className="muted small">
                        Backend: {pa.backend}{pa.backend === "fallback" ? " (tshark not available on the server)" : ""} &middot; {pa.link_layer} &middot; {pa.packets_analyzed} packets analyzed
                      </p>
                      <div className="stat-grid">
                        {pa.retry_rate_pct !== null && (
                          <StatCard label="Retry rate" value={`${pa.retry_rate_pct}%`} tone={pa.retry_rate_pct > 10 ? "warning" : "default"} />
                        )}
                        {pa.rssi_min_dbm !== null && (
                          <StatCard label="RSSI range (dBm)" value={`${pa.rssi_min_dbm} to ${pa.rssi_max_dbm}`} tone="default" />
                        )}
                        <StatCard label="Anomalies found" value={pa.anomalies.length} tone={pa.anomalies.length > 0 ? "warning" : "ok"} />
                      </div>
                      {pa.frame_type_breakdown.length > 0 && (
                        <>
                          <h3>Frame/protocol breakdown</h3>
                          <table className="fact-table">
                            <thead><tr><th>Type</th><th>Count</th></tr></thead>
                            <tbody>
                              {pa.frame_type_breakdown.slice(0, 12).map((f, i) => (
                                <tr key={i}><td>{f.label}</td><td>{f.count}</td></tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                      {pa.identity_signals.length > 0 && (
                        <>
                          <h3>Identity signals</h3>
                          <table className="fact-table">
                            <thead><tr><th>Kind</th><th>Value</th><th>Count</th></tr></thead>
                            <tbody>
                              {pa.identity_signals.slice(0, 15).map((s, i) => (
                                <tr key={i}><td>{s.kind}</td><td className="small">{s.value}</td><td>{s.count}</td></tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                      {pa.anomalies.length > 0 && (
                        <>
                          <h3>Anomalies</h3>
                          <table className="fact-table">
                            <thead><tr><th>Kind</th><th>Detail</th><th>MAC / IP</th></tr></thead>
                            <tbody>
                              {pa.anomalies.slice(0, 20).map((a, i) => (
                                <tr key={i}><td className="warn-text">{a.kind.replace(/_/g, " ")}</td><td className="small">{a.detail}</td><td className="small">{a.mac_or_ip}</td></tr>
                              ))}
                            </tbody>
                          </table>
                        </>
                      )}
                      <p className="muted small">{pa.note}</p>
                    </section>
                  ))}

                  {summary.bt_hci_summary.length === 0 && summary.packet_capture_summary.length === 0
                    && filtered.wifi_events.filter((w) => w.kind === "disconnection").length === 0 && (
                    <div className="panel"><p className="muted">No Bluetooth, Wi-Fi, or packet-capture facts parsed for any linked capture.</p></div>
                  )}
                </>
              )}

              {activeTab === "battery" && (
                <>
                  {filtered.top_battery_consumers.length > 0 ? (
                    <section className="panel">
                      <h2>Top battery consumers</h2>
                      <p className="muted small">Estimated mAh per app/UID, across all linked captures. Package is unattributed (not guessed) for shared system UIDs.</p>
                      <table className="fact-table">
                        <thead><tr><th>App / UID</th><th>Total (mAh)</th><th>Breakdown</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.top_battery_consumers.map((b, i) => (
                            <tr key={i}>
                              <td>{b.package ?? <span className="muted">{b.uid_token} (unattributed)</span>}</td>
                              <td>{b.total_mah.toFixed(2)}</td>
                              <td className="small">
                                {Object.entries(b.components_mah).map(([k, v]) => `${k}=${v.toFixed(2)}`).join(", ")}
                              </td>
                              <td><CaptureTag filename={b.original_filename} /></td>
                              <td><SourceTag source={b.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>
                  ) : (
                    <div className="panel"><p className="muted">No battery stats parsed or matched for any linked capture.</p></div>
                  )}
                </>
              )}

              {activeTab === "timeline" && (
                <>
                  <section className="panel">
                    <h2>Event timeline</h2>
                    <Timeline events={filtered.timeline} />
                  </section>

                  <section className="panel">
                    <h2>Media sessions</h2>
                    {filtered.media_sessions.length === 0 ? <p className="muted small">No media sessions parsed or matched.</p> : (
                      <table className="fact-table">
                        <thead><tr><th>Package</th><th>State</th><th>Active</th><th>Position (ms)</th><th>Capture</th><th>Cite</th></tr></thead>
                        <tbody>
                          {filtered.media_sessions.map((m, i) => (
                            <tr key={i}>
                              <td>{m.package}</td><td>{m.playback_state ?? "unknown"}</td>
                              <td>{String(m.active)}</td><td>{m.position_ms}</td>
                              <td><CaptureTag filename={m.original_filename} /></td>
                              <td><SourceTag source={m.source} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </section>
                </>
              )}
            </>
          )}
        </main>
      </div>

      <style>{`
        :root {
          --bg: #0b0f17; --panel: #121826; --panel-border: #232c3d;
          --text: #e6e9ef; --muted: #7c8798; --accent: #ff8a3d; --accent-dark: #d96f26;
          --green: #2fbf71; --amber: #d9a72f; --red: #e5484d; --orange: #e5843d; --blue: #4a9eff;
        }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); }
        .app { min-height: 100vh; background: var(--bg); color: var(--text); font-family: -apple-system, system-ui, sans-serif; }
        .topbar { padding: 20px 28px; border-bottom: 1px solid var(--panel-border); display: flex; align-items: baseline; gap: 14px; }
        .brand { font-size: 22px; font-weight: 800; color: var(--accent); letter-spacing: -0.5px; }
        .tagline { color: var(--muted); font-size: 13px; }
        .layout { display: grid; grid-template-columns: 300px 1fr; gap: 20px; padding: 20px 28px; align-items: start; }
        .sidebar { display: flex; flex-direction: column; gap: 16px; position: sticky; top: 20px; }
        .main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
        .panel {
          background: var(--panel); border: 1px solid var(--panel-border); border-radius: 10px; padding: 16px 18px;
          /* .panel is a flex child of .main, which defaults flex items to
             min-width: auto -- refusing to shrink below their widest
             content (a long stack frame, kernel message, or build
             fingerprint in a .fact-table). Without this, that content
             pushed .panel wider than the viewport and took the whole page
             with it instead of scrolling in place. overflow-x also
             happens to relax the min-width:auto default in most browsers,
             but min-width: 0 is set explicitly rather than relying on that. */
          min-width: 0;
          overflow-x: auto;
        }
        .panel h2 { margin: 0 0 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent); }
        .panel h3 { margin: 16px 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
        label { display: block; margin-bottom: 12px; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
        input[type=text], textarea, input[type=file] {
          display: block; width: 100%; margin-top: 6px; padding: 9px 10px; font: inherit; font-size: 14px;
          background: #0e1420; color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px;
        }
        textarea { resize: vertical; }
        select {
          padding: 8px 10px; font: inherit; font-size: 13px; background: #0e1420; color: var(--text);
          border: 1px solid var(--panel-border); border-radius: 6px; margin-top: 4px;
        }
        .ask-row { display: flex; align-items: flex-end; gap: 16px; margin-top: 4px; }
        .inline-label { margin-bottom: 0; flex: 0 0 auto; }
        .inline-label select { display: block; }
        button {
          padding: 9px 18px; border-radius: 6px; border: none; background: var(--accent); color: #1a0e05;
          cursor: pointer; font-weight: 700; font-size: 13px;
        }
        button:hover:not(:disabled) { background: var(--accent-dark); }
        button:disabled { opacity: 0.4; cursor: not-allowed; }
        .secondary-btn { margin-bottom: 10px; background: #273247; color: var(--text); }
        .secondary-btn:hover:not(:disabled) { background: #32405a; }
        .error { color: var(--red); padding: 12px; border: 1px solid var(--red); border-radius: 6px; white-space: pre-wrap; font-size: 13px; }
        .muted { color: var(--muted); }
        .small { font-size: 12px; }
        .warnings { color: var(--amber); font-size: 13px; padding-left: 18px; margin: 0 0 12px; }

        .capture-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
        .capture-list li { padding: 8px 10px; border-radius: 6px; cursor: pointer; border: 1px solid transparent; border-left: 3px solid transparent; }
        .capture-list li:hover { background: #0e1420; }
        .capture-list li.active { border-color: var(--accent); background: #1a1408; }
        .capture-list li.has-findings { border-left-color: var(--red); }
        .cap-name { font-size: 13px; display: flex; align-items: center; gap: 6px; }
        .sev-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--red); flex-shrink: 0; }

        .ask-hero { border-color: var(--accent); }
        .ask-hero-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
        .ask-hero-head h2 { margin-bottom: 0; }
        .scope-toggle { display: flex; gap: 4px; background: #0e1420; border: 1px solid var(--panel-border); border-radius: 8px; padding: 3px; }
        .scope-toggle button { background: transparent; color: var(--muted); padding: 6px 12px; font-size: 12px; font-weight: 600; border-radius: 6px; }
        .scope-toggle button:hover:not(:disabled) { background: transparent; color: var(--text); }
        .scope-toggle button.active { background: var(--accent); color: #1a0e05; }
        .severity-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-bottom: 14px; }
        .scan-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
        .finding-tally { display: flex; gap: 16px; margin-bottom: 10px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
        .finding-count b { font-size: 15px; }
        .finding-list { list-style: none; margin: 0 0 4px; padding: 0; display: flex; flex-direction: column; gap: 7px; }
        .finding-list li { background: #0e1420; border: 1px solid var(--panel-border); border-left: 3px solid var(--muted); border-radius: 6px; padding: 9px 12px; }
        .finding-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13px; }
        .finding-occ { font-family: ui-monospace, monospace; font-size: 12px; color: var(--amber); font-weight: 700; }
        .finding-detail { margin-top: 3px; word-break: break-word; }
        .finding-meta { display: flex; align-items: center; gap: 10px; margin-top: 5px; flex-wrap: wrap; }
        .ask-result { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--panel-border); }

        .tabbar { display: flex; gap: 2px; border-bottom: 1px solid var(--panel-border); position: sticky; top: 0; z-index: 2; background: var(--bg); padding-top: 2px; }
        .tab { background: transparent; color: var(--muted); border: none; border-radius: 8px 8px 0 0; padding: 9px 16px; font-size: 13px; font-weight: 600; }
        .tab:hover:not(:disabled) { background: var(--panel); color: var(--text); }
        .tab.active { background: var(--panel); color: var(--accent); border: 1px solid var(--panel-border); border-bottom-color: var(--panel); position: relative; top: 1px; }

        .triage-panel { position: sticky; top: 0; z-index: 2; }
        .triage-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 10px; }
        .triage-head h2 { margin-bottom: 0; }
        .triage-grid { display: grid; grid-template-columns: minmax(180px, 1.3fr) minmax(180px, 1.3fr) 130px 130px; gap: 12px; align-items: end; }
        input[type=number], input[type=time] {
          display: block; width: 100%; margin-top: 6px; padding: 9px 10px; font: inherit; font-size: 14px;
          background: #0e1420; color: var(--text); border: 1px solid var(--panel-border); border-radius: 6px;
        }

        .device-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px 24px; }
        .device-row { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; border-bottom: 1px dashed #1c2433; font-size: 13px; }
        .device-key { color: var(--muted); flex-shrink: 0; }
        .device-val { text-align: right; word-break: break-word; font-family: ui-monospace, monospace; font-size: 12px; }
        .device-info-block { margin-bottom: 14px; padding-bottom: 14px; border-bottom: 1px solid var(--panel-border); }
        .device-info-block:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }

        .capture-tag { display: inline-block; background: #1a2337; color: var(--blue); font-size: 10.5px; font-weight: 600; padding: 1px 7px; border-radius: 10px; white-space: nowrap; }

        .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; }
        .stat { background: #0e1420; border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px; }
        .stat-value { font-size: 24px; font-weight: 800; }
        .stat-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
        .stat-critical .stat-value { color: var(--red); }
        .warn-text { color: var(--amber); font-weight: 600; }
        .stat-warning .stat-value { color: var(--amber); }
        .stat-ok .stat-value { color: var(--green); }

        .fact-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .fact-table th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; padding: 6px 8px; border-bottom: 1px solid var(--panel-border); white-space: nowrap; }
        /* A single giant unbroken token (a full stack frame path, a build
           fingerprint) still wraps here rather than forcing the panel's
           scrollbar wider than it needs to be for one long cell. */
        .fact-table td { padding: 6px 8px; border-top: 1px solid #1c2433; overflow-wrap: anywhere; }
        .src { color: var(--blue); font-family: ui-monospace, monospace; font-size: 11px; white-space: nowrap; }

        .timeline { display: flex; flex-direction: column; gap: 2px; max-height: 340px; overflow-y: auto; }
        .timeline-row { display: grid; grid-template-columns: 10px 150px 1fr auto; align-items: center; gap: 10px; padding: 5px 4px; border-radius: 4px; font-size: 12px; }
        .timeline-row:hover { background: #0e1420; }
        .timeline-dot { width: 8px; height: 8px; border-radius: 50%; }
        .timeline-ts { color: var(--muted); font-family: ui-monospace, monospace; }

        .coverage-notice { border: 1px solid var(--panel-border); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; background: #0e1420; font-size: 13px; }
        .coverage-notice p { margin: 6px 0 0; }
        .coverage-notice.coverage-gap { border-color: var(--amber); }
        .coverage-notice.coverage-ok { border-color: var(--green); }
        .coverage-notice.coverage-info { border-color: var(--blue); }
        .claim-card { border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px; margin-bottom: 12px; background: #0e1420; }
        .claim-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
        .badge { color: #10131a; font-size: 11px; font-weight: 800; padding: 2px 8px; border-radius: 10px; }
        .device-badge { background: var(--blue); color: #061019; }
        .history { margin-top: 8px; font-size: 12px; background: #10151f; padding: 8px; border-radius: 6px; color: var(--muted); }
        .report { background: #0e1420; padding: 14px 16px; border-radius: 6px; font-size: 13px; max-height: 480px; overflow: auto; border: 1px solid var(--panel-border); line-height: 1.55; }
        .report-heading { margin: 16px 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent); }
        .report-heading:first-child { margin-top: 0; }
        .report-para { margin: 0 0 10px; color: var(--text); }
        .report-list { margin: 0 0 10px; padding-left: 20px; }
        .report-list li { margin-bottom: 4px; }
        .inline-code { background: #1a2337; color: var(--blue); padding: 1px 5px; border-radius: 4px; font-family: ui-monospace, monospace; font-size: 12px; }
        .follow-up-turn { margin-top: 16px; padding-top: 16px; border-top: 1px dashed var(--panel-border); }
        .follow-up-form { display: flex; align-items: flex-end; gap: 12px; margin-top: 16px; }
        .follow-up-form label { flex: 1; margin-bottom: 0; }
        .follow-up-form input { margin-top: 6px; }
        @media (max-width: 900px) {
          .layout { grid-template-columns: 1fr; }
          .sidebar, .triage-panel, .tabbar { position: static; }
          .triage-grid { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 620px) {
          .topbar, .ask-row, .triage-head, .ask-hero-head { flex-direction: column; align-items: stretch; }
          .triage-grid, .device-grid, .severity-strip { grid-template-columns: 1fr; }
          .timeline-row { grid-template-columns: 10px 1fr; }
          .timeline-ts, .timeline-label, .src { grid-column: 2; }
          .tabbar { overflow-x: auto; }
        }
      `}</style>
    </div>
  );
}
