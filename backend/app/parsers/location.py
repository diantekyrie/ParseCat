"""Parsers for location and GNSS state.

Built after a real miss: a user reported their Pokemon Go avatar jumping
between spots on a lower floor of a convention center and asked whether
there had been a GPS problem. Every relevant number was sitting in the
bugreport and ParseCat parsed none of it, so the tool correctly but
uselessly answered "cannot confirm or rule out."

Three sources, each answering a different question:

1. `dumpsys location` -- who was using location, through which provider,
   and what the last fix from each provider looked like. Also carries a
   GNSS KPI block with since-boot aggregates (time-to-first-fix, position
   accuracy, carrier-to-noise ratios).

2. `gps_signal_quality` transitions in the batterystats history -- the
   only TIME-RESOLVED measure of reception quality. Android classifies
   reception as good/poor/none; on the device studied the boundary is
   stated by the KPI block itself as a top-4-average C/N0 of 20 dB-Hz.

3. `+gps`/`-gps` history events tagged with a uid -- when a specific app
   held the GPS on, which turns "reception was bad at 12:19" into "the
   app was actively requesting fixes while reception was bad."

Deliberate limits, because this is a category where a tool would find it
very easy to overclaim:

* **Reception quality is not position error.** A "poor" interval means
  weak satellite signal. It does NOT establish that the app received a
  wrong position -- the logs record signal quality, never the coordinates
  delivered to an app. Nothing here infers position error.

* **Coordinates are treated as sensitive.** A last-known fix is the
  user's real physical location, frequently their home. Coordinates are
  parsed and stored locally, but `redacted_coords()` exists so callers
  can keep them out of anything sent to a third-party LLM; the
  diagnostic value lives in the accuracy radius and provider, not the
  latitude.

* **"none" is not "poor".** Android emits `none` both while a fix is
  being acquired and when GPS is off. Treating it as a bad-reception
  reading would invent outages at the start of every session, so it is
  kept as its own state and never counted as degraded.
"""
from __future__ import annotations

import re
from datetime import datetime

from app.parsers.base import (
    GnssKpi,
    LocationAppUsage,
    LocationProviderState,
    LocationSnapshot,
    GnssSignalInterval,
    SourceRef,
)
from app.parsers.section_extractor import Section

# "      last location=Location[network 37.737630,-122.430491 hAcc=16.568 et=+3d21h50m7s712ms alt=88.3 ...]"
LAST_LOCATION_RE = re.compile(
    r"last location=Location\[(?P<provider>\w+)\s+"
    r"(?P<lat>-?\d+\.\d+),(?P<lon>-?\d+\.\d+)"
    r"(?:\s+hAcc=(?P<hacc>[\d.]+))?"
    r"(?:.*?\bvAcc=(?P<vacc>[\d.]+))?"
)
# The GPS provider's fix carries a satellite bundle the others don't.
SAT_BUNDLE_RE = re.compile(r"satellites=(?P<sats>\d+), maxCn0=(?P<max>\d+), meanCn0=(?P<mean>\d+)")

PROVIDER_HEADER_RE = re.compile(r"^    (?P<name>[\w ]+) provider:\s*$")

# "      10311/com.nianticlabs.pokemongo: min/max interval = 0s/1s, total/active/foreground
#        duration = +15h13m41s259ms/+15h13m41s163ms/+40m41s545ms, locations = 163"
APP_USAGE_RE = re.compile(
    r"^\s+(?P<uid>\d+)/(?P<package>[\w.:]+)(?:\[(?P<tag>[^\]]*)\])?:\s+"
    r"min/max interval = (?P<min_iv>\S+?)/(?P<max_iv>\S+?), "
    r"total/active/foreground duration = (?P<total>\S+?)/(?P<active>\S+?)/(?P<fg>\S+?), "
    r"locations = (?P<locations>\d+)"
)
USAGE_PROVIDER_HEADER_RE = re.compile(r"^\s{4}(?P<name>\w+):\s*$")

KPI_FIELDS = {
    "Percentage location failure": "location_failure_pct",
    "Number of location reports": "location_reports",
    "Number of TTFF reports": "ttff_reports",
    "TTFF mean (sec)": "ttff_mean_sec",
    "TTFF standard deviation (sec)": "ttff_stddev_sec",
    "Number of position accuracy reports": "accuracy_reports",
    "Position accuracy mean (m)": "accuracy_mean_m",
    "Position accuracy standard deviation (m)": "accuracy_stddev_m",
    "Top 4 Avg CN0 mean (dB-Hz)": "cn0_mean_dbhz",
    "Top 4 Avg CN0 standard deviation (dB-Hz)": "cn0_stddev_dbhz",
}
KPI_LINE_RE = re.compile(r"^\s*(?P<key>[^:]+):\s*(?P<value>-?[\d.]+)\s*$")
CONSTELLATION_RE = re.compile(r"^\s*Used-in-fix constellation types:\s*(?P<value>.+?)\s*$")
HW_MODEL_RE = re.compile(r"^\s*GNSS Hardware Model Name:\s*(?P<value>.+?)\s*$")
# "Amount of time (while on battery) Top 4 Avg CN0 > 20.0 dB-Hz (min): 112.14"
CN0_TIME_RE = re.compile(
    r"^\s*Amount of time \(while on battery\) Top 4 Avg CN0 (?P<op>[<>]=?) "
    r"(?P<threshold>[\d.]+) dB-Hz \(min\):\s*(?P<value>[\d.]+)"
)

# Battery history lines are indented and look like:
# "  08-28 12:19:43.377 094 e2902820 +gps gps_signal_quality=poor +state=10311:\"gnss\""
HISTORY_TS_RE = re.compile(r"^\s*(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(?P<ms>\d{3})\s+\d{3}\s+\w{8}\s")
SIGNAL_QUALITY_RE = re.compile(r"gps_signal_quality=(?P<quality>\w+)")
GPS_STATE_RE = re.compile(r"(?P<sign>[+-])state=(?P<uid>\d+):\"gnss\"")
GPS_FLAG_RE = re.compile(r"(?<![\w])(?P<sign>[+-])gps(?![\w_])")


def _f(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def redacted_coords(lat: float | None, lon: float | None) -> str:
    """A coarse, non-identifying stand-in for a real fix.

    Rounded to one decimal degree -- roughly 11 km, enough to distinguish
    "a fix existed here" from "a fix existed 300 km away" without carrying
    someone's home address into a third-party API request. The precise
    values stay in the local database for the UI.
    """
    if lat is None or lon is None:
        return "unknown"
    return f"~{lat:.1f}, {lon:.1f}"


def parse_location_dump(section: Section) -> LocationSnapshot | None:
    """Parses `dumpsys location`: providers, last fixes, per-app usage, KPIs."""
    providers: dict[str, LocationProviderState] = {}
    app_usage: list[LocationAppUsage] = []
    kpi_values: dict[str, float | None] = {}
    constellations = hw_model = None
    cn0_time_above_min = cn0_time_below_min = cn0_threshold = None
    location_enabled: bool | None = None

    current_provider: str | None = None
    usage_provider: str | None = None
    in_usage_block = False
    in_kpi = False

    for i, raw in enumerate(section.lines):
        abs_line = section.line_start + i

        if raw.strip().startswith("Location Setting:"):
            location_enabled = None  # values follow on subsequent "[u0] true" lines
        m = re.match(r"^\s*\[u\d+\]\s+(true|false)\s*$", raw)
        if m and location_enabled is None:
            location_enabled = m.group(1) == "true"

        if raw.strip() == "Historical Aggregate Location Provider Data:":
            in_usage_block, current_provider = True, None
            continue
        if in_usage_block:
            if raw.strip().endswith(":") and not raw.startswith("      "):
                # A new top-level heading ends the usage block.
                if not USAGE_PROVIDER_HEADER_RE.match(raw):
                    in_usage_block = False
                    continue
            ph = USAGE_PROVIDER_HEADER_RE.match(raw)
            if ph:
                usage_provider = ph.group("name")
                continue
            um = APP_USAGE_RE.match(raw)
            if um and usage_provider:
                app_usage.append(LocationAppUsage(
                    provider=usage_provider,
                    uid=int(um.group("uid")),
                    package=um.group("package"),
                    tag=um.group("tag"),
                    min_interval=um.group("min_iv"),
                    max_interval=um.group("max_iv"),
                    total_duration=um.group("total"),
                    foreground_duration=um.group("fg"),
                    locations=int(um.group("locations")),
                    source_ref=SourceRef(section.name, abs_line, abs_line),
                ))
                continue

        ph = PROVIDER_HEADER_RE.match(raw)
        if ph:
            current_provider = ph.group("name").strip()
            providers.setdefault(current_provider, LocationProviderState(
                name=current_provider, last_fix_provider=None, latitude=None, longitude=None,
                horizontal_accuracy_m=None, satellites=None, max_cn0=None, mean_cn0=None,
                source_ref=SourceRef(section.name, abs_line, abs_line),
            ))
            continue

        if current_provider and "last location=Location[" in raw:
            lm = LAST_LOCATION_RE.search(raw)
            if lm:
                st = providers[current_provider]
                # Both users (u0/u10) print the same fix; the first wins and
                # the duplicate is ignored rather than overwriting.
                if st.latitude is None:
                    sat = SAT_BUNDLE_RE.search(raw)
                    providers[current_provider] = LocationProviderState(
                        name=current_provider,
                        last_fix_provider=lm.group("provider"),
                        latitude=_f(lm.group("lat")), longitude=_f(lm.group("lon")),
                        horizontal_accuracy_m=_f(lm.group("hacc")),
                        satellites=int(sat.group("sats")) if sat else None,
                        max_cn0=_f(sat.group("max")) if sat else None,
                        mean_cn0=_f(sat.group("mean")) if sat else None,
                        source_ref=SourceRef(section.name, abs_line, abs_line),
                    )
            continue

        if "GNSS_KPI_START" in raw:
            in_kpi = True
            continue
        if "GNSS_KPI_END" in raw:
            in_kpi = False
            continue
        if in_kpi:
            km = KPI_LINE_RE.match(raw)
            if km:
                field = KPI_FIELDS.get(km.group("key").strip())
                if field:
                    kpi_values[field] = _f(km.group("value"))
                continue
            cm = CONSTELLATION_RE.match(raw)
            if cm:
                constellations = cm.group("value").strip()
                continue

        tm = CN0_TIME_RE.match(raw)
        if tm:
            cn0_threshold = _f(tm.group("threshold"))
            if tm.group("op").startswith(">"):
                cn0_time_above_min = _f(tm.group("value"))
            else:
                cn0_time_below_min = _f(tm.group("value"))
            continue

        hm = HW_MODEL_RE.match(raw)
        if hm:
            hw_model = hm.group("value").strip()

    if not providers and not app_usage and not kpi_values:
        return None

    kpi = GnssKpi(
        location_failure_pct=kpi_values.get("location_failure_pct"),
        location_reports=int(kpi_values["location_reports"]) if kpi_values.get("location_reports") else None,
        ttff_reports=int(kpi_values["ttff_reports"]) if kpi_values.get("ttff_reports") else None,
        ttff_mean_sec=kpi_values.get("ttff_mean_sec"),
        ttff_stddev_sec=kpi_values.get("ttff_stddev_sec"),
        accuracy_reports=int(kpi_values["accuracy_reports"]) if kpi_values.get("accuracy_reports") else None,
        accuracy_mean_m=kpi_values.get("accuracy_mean_m"),
        accuracy_stddev_m=kpi_values.get("accuracy_stddev_m"),
        cn0_mean_dbhz=kpi_values.get("cn0_mean_dbhz"),
        cn0_stddev_dbhz=kpi_values.get("cn0_stddev_dbhz"),
        cn0_threshold_dbhz=cn0_threshold,
        cn0_time_above_threshold_min=cn0_time_above_min,
        cn0_time_below_threshold_min=cn0_time_below_min,
        constellations=constellations,
    ) if (kpi_values or cn0_threshold) else None

    return LocationSnapshot(
        location_enabled=location_enabled,
        gnss_hardware_model=hw_model,
        providers=list(providers.values()),
        app_usage=app_usage,
        kpi=kpi,
        source_ref=SourceRef(section.name, section.line_start, section.line_end),
    )


def parse_gnss_signal_intervals(section: Section) -> list[GnssSignalInterval]:
    """Turns `gps_signal_quality` transitions into closed intervals.

    Each interval records the quality that held from one transition to the
    next, and which uids had GPS active during it. An interval is only
    emitted once its END is known, so a trailing open state at the end of
    the history is dropped rather than given an invented duration.
    """
    events: list[tuple[datetime, str, int, str | None, int]] = []
    active_uids: set[int] = set()
    gps_on = False

    for i, raw in enumerate(section.lines):
        tm = HISTORY_TS_RE.match(raw)
        if not tm:
            continue
        try:
            ts = datetime.strptime(tm.group("ts"), "%m-%d %H:%M:%S")
        except ValueError:
            continue
        abs_line = section.line_start + i

        for sm in GPS_STATE_RE.finditer(raw):
            uid = int(sm.group("uid"))
            active_uids.add(uid) if sm.group("sign") == "+" else active_uids.discard(uid)
        fm = GPS_FLAG_RE.search(raw)
        if fm:
            gps_on = fm.group("sign") == "+"

        qm = SIGNAL_QUALITY_RE.search(raw)
        if qm:
            events.append((ts, qm.group("quality"), abs_line,
                           ",".join(str(u) for u in sorted(active_uids)) or None,
                           1 if gps_on else 0))

    intervals: list[GnssSignalInterval] = []
    for (start, quality, line, uids, on), (end, _q, _l, _u, _o) in zip(events, events[1:]):
        if end < start:
            # The battery history is not strictly monotonic. A real capture
            # stepped backwards 5 seconds mid-history (18:37:39 -> 18:37:34),
            # almost certainly a clock correction landing between two
            # entries. Pairing across that produces a negative duration,
            # which would then be summed into "total degraded seconds" and
            # quietly understate it. Treat the step as a discontinuity and
            # emit no interval rather than a nonsense one.
            continue
        intervals.append(GnssSignalInterval(
            quality=quality,
            start_timestamp=start.strftime("%m-%d %H:%M:%S"),
            end_timestamp=end.strftime("%m-%d %H:%M:%S"),
            duration_sec=int((end - start).total_seconds()),
            active_uids=uids,
            gps_active=bool(on),
            source_ref=SourceRef(section.name, line, line),
        ))
    return intervals
