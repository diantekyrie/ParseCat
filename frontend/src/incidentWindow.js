/** Incident-window matching used by the timeline/filter UI.
 *
 * Dated stamps (ISO or MM-DD) compare calendar minutes and do not wrap at 24h.
 * Time-only stamps may wrap midnight, because they have no date to order by.
 */
export function timestampOrderMinutes(timestamp) {
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

export function matchesIncidentWindow(timestamp, center, windowMinutes) {
  if (!center) return true;
  const event = timestampOrderMinutes(timestamp);
  const at = timestampOrderMinutes(center);
  if (!event || !at) return false;
  const delta = Math.abs(event.minutes - at.minutes);
  if (event.dated || at.dated) return delta <= windowMinutes;
  return Math.min(delta, 1440 - delta) <= windowMinutes;
}
