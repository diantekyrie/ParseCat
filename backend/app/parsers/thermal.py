"""Parser for `dumpsys thermalservice` -- a point-in-time snapshot of
every temperature sensor Android's thermal HAL knows about, plus the
system-wide throttling status it has already computed.

    Thermal Status: 0
    Cached temperatures:
        Temperature{mValue=51.000004, mType=0, mName=LITTLE, mStatus=0}
        Temperature{mValue=46.000004, mType=1, mName=GPU, mStatus=0}
    Current temperatures from HAL:
        Temperature{mValue=50.7, mType=0, mName=AP, mStatus=0}

`mType` and `mStatus` (and the overall "Thermal Status") are the integer
codes Android's IThermal HAL (`ThrottlingSeverity`, `TemperatureType`)
defines. Both are decorated with a human label here, but the raw integer
always rides along -- an unrecognized or future code degrades to a label
like "type_11" rather than being guessed at or dropped, the same
disclosed-uncertainty approach used for SELinux's three-state `enforcing`.

The section actually prints the SAME sensors twice: once under "Cached
temperatures" (Android's app-facing getCurrentTemperatures() cache) and
again under "Current temperatures from HAL" (the live HAL readout). A
capture verified byte-for-byte (Pixel and Samsung both have this
structure) showed each block's readings differ slightly -- e.g. AP/SKIN
a couple tenths of a degree apart between the two -- so they are not
interchangeable duplicates to merge, and blindly matching every
`Temperature{...}` line regardless of which block it's in double-counts
every sensor. Only the "Current temperatures from HAL" block is kept,
since it is the more current of the two and explicitly labeled as such;
"Cached temperatures" is skipped entirely rather than merged or averaged.
"""
from __future__ import annotations

import re

from app.parsers.base import ThermalSensorReading, ThermalSnapshot, SourceRef
from app.parsers.section_extractor import Section

OVERALL_STATUS_RE = re.compile(r"^Thermal Status:\s*(?P<code>-?\d+)\s*$")
CACHED_HEADER_RE = re.compile(r"^Cached temperatures:\s*$")
HAL_CURRENT_HEADER_RE = re.compile(r"^Current temperatures from HAL:\s*$")
# Any other top-level (unindented) heading ends whichever temperature block
# we were in -- covers "Current cooling devices from HAL:", "HAL Ready:",
# etc. without having to name every one of them.
OTHER_HEADING_RE = re.compile(r"^[A-Za-z].*:\s*$")
TEMPERATURE_RE = re.compile(
    r"Temperature\{mValue=(?P<value>-?[\d.E+-]+),\s*mType=(?P<type>-?\d+),\s*"
    r"mName=(?P<name>[^,]+),\s*mStatus=(?P<status>-?\d+)\}"
)

# Android's IThermal HAL ThrottlingSeverity enum.
STATUS_NAMES = {
    0: "none", 1: "light", 2: "moderate", 3: "severe",
    4: "critical", 5: "emergency", 6: "shutdown",
}

# Android's IThermal HAL TemperatureType enum. -1 is TYPE_UNKNOWN and covers
# most vendor-custom "VIRTUAL-*" sensors seen in real captures -- that is
# the HAL's own label for them, not a gap in this mapping.
TYPE_NAMES = {
    -1: "unknown", 0: "cpu", 1: "gpu", 2: "battery", 3: "skin",
    4: "usb_port", 5: "power_amplifier", 6: "bcl_voltage",
    7: "bcl_current", 8: "bcl_percentage", 9: "npu",
}


# A real Pixel capture reported GPU/TPU at mValue=-3.4028235E38 -- the
# float32 near-min value, used by at least one thermal HAL as a
# sentinel for "no reading available" rather than an actual temperature.
# No real hardware/battery/ambient sensor is outside this range, so
# anything past it is treated the same way: not a measurement.
_PLAUSIBLE_MIN_C, _PLAUSIBLE_MAX_C = -100.0, 300.0


def _f(value: str) -> float | None:
    try:
        v = float(value)
    except ValueError:
        return None
    if not (_PLAUSIBLE_MIN_C <= v <= _PLAUSIBLE_MAX_C):
        return None
    return v


def parse_thermal_snapshot(section: Section) -> ThermalSnapshot | None:
    overall_code: int | None = None
    # Kept as two separate lists rather than one, precisely so neither block
    # can silently double the other -- see the module docstring.
    by_block: dict[str, list[ThermalSensorReading]] = {"cached": [], "hal_current": []}
    # None = not in either block yet.
    block: str | None = None

    for raw in section.lines:
        m = OVERALL_STATUS_RE.match(raw)
        if m and overall_code is None:
            overall_code = int(m.group("code"))
            continue

        if CACHED_HEADER_RE.match(raw):
            block = "cached"
            continue
        if HAL_CURRENT_HEADER_RE.match(raw):
            block = "hal_current"
            continue
        if block is not None and not raw.startswith("\t") and not raw.startswith(" ") \
           and OTHER_HEADING_RE.match(raw):
            block = None  # some other section heading -- both blocks are over

        if block is None:
            continue
        tm = TEMPERATURE_RE.search(raw)
        if tm:
            type_code = int(tm.group("type"))
            status_code = int(tm.group("status"))
            by_block[block].append(ThermalSensorReading(
                name=tm.group("name").strip(),
                value_c=_f(tm.group("value")),
                type_code=type_code,
                type_name=TYPE_NAMES.get(type_code, f"type_{type_code}"),
                status_code=status_code,
                status_name=STATUS_NAMES.get(status_code, f"status_{status_code}"),
            ))

    # Prefer "Current temperatures from HAL" -- it's the more current of the
    # two and explicitly labeled as such. Fall back to "Cached temperatures"
    # only if a build doesn't print the HAL-current block at all, rather
    # than silently reporting zero sensors when real data was available.
    sensors = by_block["hal_current"] or by_block["cached"]

    if overall_code is None and not sensors:
        return None

    return ThermalSnapshot(
        overall_status_code=overall_code,
        overall_status_name=STATUS_NAMES.get(overall_code, f"status_{overall_code}") if overall_code is not None else None,
        sensors=sensors,
        source_ref=SourceRef(section.name, section.line_start, section.line_end),
    )
