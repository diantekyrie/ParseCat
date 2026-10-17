import { useState } from "react";
import {
  HOW_TO_CAPTURE_AOSP_URL,
  HOW_TO_CAPTURE_DOCS_HINT,
  HOW_TO_CAPTURE_INTRO,
  HOW_TO_CAPTURE_STEPS,
  HOW_TO_CAPTURE_TITLE,
} from "./howToCapture.js";

/**
 * Collapsible sidebar panel: HCI snoop before repro + how to take a bugreport.
 * Draft Msg8 UI — content only; no network calls, no sample captures.
 */
export default function HowToCapturePanel({ defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="panel how-to-capture-panel" data-testid="how-to-capture">
      <button
        type="button"
        className="how-to-capture-toggle"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span>{HOW_TO_CAPTURE_TITLE}</span>
        <span className="how-to-capture-chevron" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
      </button>
      {open && (
        <div className="how-to-capture-body">
          <p className="muted small">{HOW_TO_CAPTURE_INTRO}</p>
          <ol className="how-to-capture-list">
            {HOW_TO_CAPTURE_STEPS.map((step) => (
              <li key={step.id} data-step-id={step.id}>
                <strong>{step.title}</strong>
                <p className="muted small">{step.body}</p>
              </li>
            ))}
          </ol>
          <p className="muted small how-to-capture-docs">{HOW_TO_CAPTURE_DOCS_HINT}</p>
          <p className="muted small">
            AOSP HCI snoop steps:{" "}
            <a href={HOW_TO_CAPTURE_AOSP_URL} target="_blank" rel="noreferrer">
              Verify and debug (Bluetooth)
            </a>
          </p>
        </div>
      )}
    </section>
  );
}
