"""Parser for the kernel ring buffer (`dmesg`-style KERNEL LOG section).

Lines look like:

    <6>[83852.874840][ T4249] google-ufshcd 3c400000.ufs: applying calibration took 4214 usec
    <3>[83858.955847][T23105] alarmtimer alarmtimer.4.auto: PM: failed to suspend: error -16

`<N>` is the standard syslog priority (0 emerg .. 7 debug; LOWER is worse).
The bracketed number is seconds since boot -- NOT wall-clock time. There is
no reliable anchor in a bugreport to convert kernel-log boot-relative time
to a wall-clock timestamp, so it is kept in its native form; inventing a
conversion would silently misplace every event by however wrong the anchor
guess was.

Only warning-or-worse lines are kept (priority <= 4), plus anything
matching an explicit panic-family signature regardless of priority --
those signatures are occasionally logged at a benign-looking level. A
typical bugreport's kernel log runs 8,000-12,000 lines and the overwhelming
majority is routine driver chatter (radio firmware, display state, wifi
power management) that would drown any real fault if kept unfiltered.
"""
from __future__ import annotations

import re

from app.parsers.base import KernelLogEvent, SourceRef
from app.parsers.section_extractor import Section

KERNEL_LINE_RE = re.compile(
    r"^<(?P<pri>\d)>\[\s*(?P<sec>\d+\.\d+)\]\[\s*(?P<thread>\S+)\]\s*(?P<msg>.*)$"
)

PRIORITY_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# Signatures worth keeping even if the kernel logged them at a non-alarming
# priority. Real-world kernels are inconsistent about this -- a BUG_ON can
# print at KERN_ERR or KERN_CRIT depending on the calling code.
PANIC_FAMILY_RE = re.compile(
    r"\b(?:kernel panic|panic|oops|BUG:|BUG ON|call trace|watchdog.*bark|hard lockup|soft lockup)\b",
    re.IGNORECASE,
)

DEFAULT_MAX_PRIORITY = 4  # keep <=4 (warning/err/crit/alert/emerg) unconditionally


def parse_kernel_log(section: Section, max_priority: int = DEFAULT_MAX_PRIORITY) -> list[KernelLogEvent]:
    out: list[KernelLogEvent] = []
    for i, raw in enumerate(section.lines):
        m = KERNEL_LINE_RE.match(raw)
        if not m:
            continue
        pri = int(m.group("pri"))
        msg = m.group("msg").strip()
        is_panic = bool(PANIC_FAMILY_RE.search(msg))
        if pri > max_priority and not is_panic:
            continue

        abs_line = section.line_start + i
        out.append(KernelLogEvent(
            boot_relative_sec=float(m.group("sec")),
            priority=pri,
            priority_name=PRIORITY_NAMES.get(pri, f"priority_{pri}"),
            thread=m.group("thread").strip() or None,
            message=msg,
            is_panic_family=is_panic,
            source_ref=SourceRef(section.name, abs_line, abs_line),
        ))
    return out
