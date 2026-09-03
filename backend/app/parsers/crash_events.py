"""Parser for Java `FATAL EXCEPTION` crashes in the system log.

    08-19 21:11:56.218 ... E AndroidRuntime: FATAL EXCEPTION: main
    08-19 21:11:56.218 ... E AndroidRuntime: Process: com.disney.wdpro.dlr, PID: 2974
    08-19 21:11:56.218 ... E AndroidRuntime: java.lang.RuntimeException: Unable to create application ...
    08-19 21:11:56.218 ... E AndroidRuntime: 	at android.app.ActivityThread.handleBindApplication(...)
    ... (more frames) ...
    08-19 21:11:56.218 ... E AndroidRuntime: Caused by: java.lang.RuntimeException: 25
    08-19 21:11:56.218 ... E AndroidRuntime: 	at com.assaabloy.mobilekeys.api.MobileKeysApi.initialize(...)
    ... (more frames, possibly more "Caused by:" links) ...

The top-level exception is frequently a generic wrapper ("Unable to create
application X") -- the DEEPEST "Caused by:" in the chain is usually the
actual root cause, so it's parsed out separately rather than left buried in
an unparsed stack trace.

Native crashes (tombstones) are not text in this section at all -- see
ingestion.list_native_crash_files, which reads them straight from the zip's
file listing.
"""
from __future__ import annotations

import re

from app.parsers.base import CrashEvent, SourceRef
from app.parsers.section_extractor import Section

LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\d+ E AndroidRuntime: (?P<rest>.*)$"
)
FATAL_RE = re.compile(r"^FATAL EXCEPTION: (?P<thread>.+)$")
PROCESS_RE = re.compile(r"^Process: (?P<pkg>[\w.\-:]+), PID: (?P<pid>\d+)$")
EXCEPTION_RE = re.compile(r"^([\w.$]*(?:Exception|Error)[\w.$]*): ?(.*)$")
CAUSED_BY_RE = re.compile(r"^Caused by: ([\w.$]*(?:Exception|Error)[\w.$]*): ?(.*)$")
FRAME_RE = re.compile(r"^\s*at (.+)$")

MAX_BLOCK_LINES = 500  # generous cap on one crash's stack trace + all "Caused by:" links


def parse_crash_events(section: Section) -> list[CrashEvent]:
    out: list[CrashEvent] = []
    n = len(section.lines)
    i = 0
    while i < n:
        m = LOG_LINE_RE.match(section.lines[i])
        if not m or not FATAL_RE.match(m.group("rest")):
            i += 1
            continue

        thread = FATAL_RE.match(m.group("rest")).group("thread")
        ts = m.group("ts")
        start_line = section.line_start + i

        package = pid = exception_class = message = None
        root_cause_class = root_cause_message = root_cause_frame = None
        end_line = start_line
        found_top_exception = False
        awaiting_root_frame = False

        j = i + 1
        limit = min(n, i + MAX_BLOCK_LINES)
        while j < limit:
            m2 = LOG_LINE_RE.match(section.lines[j])
            if not m2:
                break  # crash block ends where consecutive AndroidRuntime lines end
            rest = m2.group("rest")

            if FATAL_RE.match(rest):
                # A new crash starts here -- stop. Crashes can be
                # back-to-back with no gap (e.g. an app crashing twice in
                # under 10 seconds), and without this check the inner scan
                # ran straight through the boundary into a LATER, unrelated
                # crash's Process:/Caused-by lines and silently overwrote
                # this crash's package and root cause with the wrong
                # crash's data. The outer loop still visits this line on
                # its own and parses it as its own CrashEvent.
                break

            end_line = section.line_start + j

            pm = PROCESS_RE.match(rest)
            if pm:
                package = pm.group("pkg")
                pid = int(pm.group("pid"))
                j += 1
                continue

            cb = CAUSED_BY_RE.match(rest)
            if cb:
                # Each "Caused by:" replaces the previous one -- we keep the
                # DEEPEST (last) link in the chain as the root cause.
                root_cause_class, root_cause_message = cb.group(1), cb.group(2)
                root_cause_frame = None
                awaiting_root_frame = True
                j += 1
                continue

            if awaiting_root_frame:
                fm = FRAME_RE.match(rest)
                if fm:
                    root_cause_frame = fm.group(1)
                awaiting_root_frame = False
                j += 1
                continue

            if not found_top_exception:
                em = EXCEPTION_RE.match(rest)
                if em:
                    exception_class, message = em.group(1), em.group(2)
                    found_top_exception = True
                    j += 1
                    continue

            j += 1

        out.append(CrashEvent(
            timestamp=ts, thread=thread, package=package, pid=pid,
            exception_class=exception_class, message=message,
            root_cause_class=root_cause_class, root_cause_message=root_cause_message,
            root_cause_frame=root_cause_frame,
            source_ref=SourceRef(section.name, start_line, end_line),
        ))
        i += 1

    return out
