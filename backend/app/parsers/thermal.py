"""Parser for `dumpsys thermalservice` -- a point-in-time snapshot of
every temperature sensor Android's thermal HAL knows about, plus the
system-wide throttling status it has already computed.

    Thermal Status: 0
    Cached temperatures:
        Temperature{mValue=51.000004, mType=0, mName=LITTLE, mStatus=0}
        Temperature{mValue=46.000004, mType=1, mName=GPU, mStatus=0}

`mType` and `mStatus` (and the overall "Thermal Status") are the integer
codes Android's IThermal HAL (`ThrottlingSeverity`, `TemperatureType`)
defines. Both are decorated with a human label here, but the raw integer
always rides along -- an unrecognized or future code degrades to a label
like "type_11" rather than being guessed at or dropped, the same
disclosed-uncertainty approach used for SELinux's three-state `enforcing`.
"""
from __future__ import annotations

import re

from app.parsers.base import ThermalSensorReading, ThermalSnapshot, SourceRef
from app.parsers.section_extractor import Section

OVERALL_STATUS_RE = re.compile(r"^Thermal Status:\s*(?P<code>-?\d+)\s*$")
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


def _f(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return float("nan")


def parse_thermal_snapshot(section: Section) -> ThermalSnapshot | None:
    overall_code: int | None = None
    sensors: list[ThermalSensorReading] = []

    for raw in section.lines:
        m = OVERALL_STATUS_RE.match(raw)
        if m and overall_code is None:
            overall_code = int(m.group("code"))
            continue
        tm = TEMPERATURE_RE.search(raw)
        if tm:
            type_code = int(tm.group("type"))
            status_code = int(tm.group("status"))
            sensors.append(ThermalSensorReading(
                name=tm.group("name").strip(),
                value_c=_f(tm.group("value")),
                type_code=type_code,
                type_name=TYPE_NAMES.get(type_code, f"type_{type_code}"),
                status_code=status_code,
                status_name=STATUS_NAMES.get(status_code, f"status_{status_code}"),
            ))

    if overall_code is None and not sensors:
        return None

    return ThermalSnapshot(
        overall_status_code=overall_code,
        overall_status_name=STATUS_NAMES.get(overall_code, f"status_{overall_code}") if overall_code is not None else None,
        sensors=sensors,
        source_ref=SourceRef(section.name, section.line_start, section.line_end),
    )
