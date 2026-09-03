import { useEffect, useState, useCallback, useMemo, useRef } from "react";

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

function timestampOrderMinutes(timestamp) {
  if (!timestamp) return null;
  const s = String(timestamp);
  const iso = s.match(/(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})/);
  if (iso) {
    return { dated: true, minutes: (Number(iso[2]) * 31 + Number(iso[3])) * 1440 + Number(iso[4]) * 60 + Number(iso[5]) };
  }
  const md = s.match(/\b(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})/);
  if (md) {
    return { dated: true, minutes: (Number(md[1]) * 31 + Number(md[2])) * 1440 + Number(md[3]) * 60 + Number(md[4]) };
  }
  const hm = s.match(/\b(\d{1,2}):(\d{2})(?::\d{2}(?:\.\d+)?)?\b/);
  if (!hm) return null;
  return { dated: false, minutes: Number(hm[1]) * 60 + Number(hm[2]) };
}

function matchesIncidentWindow(timestamp, center, windowMinutes) {
  if (!center) return true;
  const event = timestampOrderMinutes(timestamp);
  const at = timestampOrderMinutes(center);
  if (!event || !at) return false;
  const delta = Math.abs(event.minutes - at.minutes);
  if (event.dated || at.dated) return delta <= windowMinutes;
  return Math.min(delta, 1440 - delta) <= windowMinutes;
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
