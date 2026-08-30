"""Parser for ANR (Application Not Responding) evidence -- two different
file flavors, both under FS/data/anr/ inside the bugreport zip (separate
files, not text inside the flattened bugreport txt).

1. `anr_<timestamp>` -- the ANR record itself. Always starts with:

       Subject: Process ProcessRecord{2e7636c 16041:com.disney.wdpro.dlr/u0a335} failed to complete startup

   which alone gives pid, package, and the failure reason. Some ANRs (the
   binder-starvation kind, typically a stuck service or broadcast) also
   carry Timeout/TimeoutStart/RssKb fields and a "----- dumping pid: N"
   block listing which binder threads were mid-transaction when the ANR
   fired -- direct evidence of what the process was stuck on, not an
   inference from thread state.

2. `trace_<N>` -- a full DALVIK THREADS dump (same format as the
   vm_traces_just_now bugreport section) written for the specific ANR'd
   process. This is the file that answers "what was the main thread
   actually doing" -- its state, held mutexes, and top stack frames.
   There is no reliable filename linkage between an anr_* file and its
   trace_N (observed real captures carry no cross-reference field), so
   the two are parsed and reported as separate, self-standing evidence
   rather than force-matched.
"""
from __future__ import annotations

import re

from app.parsers.base import AnrBlockingThread, AnrFacts, AnrMainThreadSnapshot, SourceRef

SUBJECT_RE = re.compile(
    r"^Subject: Process ProcessRecord\{[0-9a-f]+ (?P<pid>\d+):(?P<pkg>[\w.]+)/\S+\} (?P<reason>.+)$"
)

# Filenames look like "anr_2026-07-22-17-38-38-800"
FILENAME_TS_RE = re.compile(r"^anr_(?P<ts>[\d-]+)$")

TIMEOUT_RE = re.compile(r"^Timeout:\s*(?P<ms>\d+)\s*$")
RSS_RE = re.compile(r"^RssKb:\s*(?P<kb>\d+)\s*$")

DUMPING_PID_RE = re.compile(r"^----- dumping pid: (?P<pid>\d+) at")
INCOMING_TXN_RE = re.compile(
    r"^\s*incoming transaction \d+: \S+ from (?P<from_pid>\d+):\d+ to (?P<to_pid>\d+):(?P<thread>\d+) "
    r".*?elapsed (?P<elapsed>\d+)ms"
)

# trace_N files (and vm_traces_just_now) use this same "----- pid N at TS -----" delimiter.
TRACE_PID_HEADER_RE = re.compile(r"^----- pid (?P<pid>\d+) at ")
CMD_LINE_RE = re.compile(r"^Cmd line:\s*(?P<cmd>.+)$")
THREAD_HEADER_RE = re.compile(r'^"(?P<name>[^"]+)"[^\n]*\btid=\d+\s+(?P<state>\S+)\s*$')
HELD_MUTEXES_RE = re.compile(r"held mutexes=(?P<val>.*)$")


def parse_anr(filename: str, text: str) -> AnrFacts:
    lines = text.splitlines()
    subject_line = lines[0] if lines else ""
    m = SUBJECT_RE.match(subject_line)

    ts_m = FILENAME_TS_RE.match(filename)
    timestamp = ts_m.group("ts") if ts_m else None

    timeout_ms = rss_kb = None
    blocking_threads: list[AnrBlockingThread] = []
    current_pid: int | None = None

    for i, line in enumerate(lines):
        tm = TIMEOUT_RE.match(line)
        if tm and timeout_ms is None:
            timeout_ms = int(tm.group("ms"))
            continue
        rm = RSS_RE.match(line)
        if rm and rss_kb is None:
            # RssKb (resident set) is the field that means "was the process
            # itself under memory pressure" -- RssHwmKb is the high-water
            # mark and is a different, less current, number.
            rss_kb = int(rm.group("kb"))
            continue
        dm = DUMPING_PID_RE.match(line)
        if dm:
            current_pid = int(dm.group("pid"))
            continue
        xm = INCOMING_TXN_RE.match(line)
        if xm and current_pid is not None:
            blocking_threads.append(AnrBlockingThread(
                thread_id=int(xm.group("thread")),
                from_pid=int(xm.group("from_pid")),
                to_pid=int(xm.group("to_pid")),
                elapsed_ms=int(xm.group("elapsed")),
                source_ref=SourceRef(f"anr/{filename}", i + 1, i + 1),
            ))

    return AnrFacts(
        filename=filename,
        timestamp=timestamp,
        subject=subject_line,
        pid=int(m.group("pid")) if m else None,
        package=m.group("pkg") if m else None,
        reason=m.group("reason") if m else None,
        timeout_ms=timeout_ms,
        rss_kb=rss_kb,
        blocking_threads=blocking_threads,
    )


def parse_anr_trace_dump(filename: str, text: str, max_frames: int = 6) -> list[AnrMainThreadSnapshot]:
    """Parses a trace_<N> file's DALVIK THREADS dump, keeping only each
    process's "main" thread -- the one whose blocking actually causes an
    ANR. A trace_N file can contain 100+ threads across the process; the
    other threads say nothing about why the app stopped responding.
    """
    out: list[AnrMainThreadSnapshot] = []
    lines = text.splitlines()

    pid = cmd = None
    in_main = False
    state = held_mutexes = None
    frames: list[str] = []

    def flush():
        if pid is not None and state is not None:
            out.append(AnrMainThreadSnapshot(
                pid=pid, process=cmd or "unknown", state=state,
                held_mutexes=held_mutexes, top_frames=list(frames),
                source_ref=SourceRef(f"anr/{filename}", 1, len(lines)),
            ))

    for line in lines:
        hm = TRACE_PID_HEADER_RE.match(line)
        if hm:
            flush()
            pid, cmd, in_main = int(hm.group("pid")), None, False
            state = held_mutexes = None
            frames = []
            continue
        cm = CMD_LINE_RE.match(line)
        if cm and pid is not None:
            cmd = cm.group("cmd").strip()
            continue

        th = THREAD_HEADER_RE.match(line)
        if th:
            in_main = th.group("name") == "main"
            if in_main:
                state = th.group("state")
            continue

        if not in_main:
            continue
        mx = HELD_MUTEXES_RE.search(line)
        if mx:
            # Android omits printing anything after "held mutexes=" when the
            # thread holds nothing -- an empty string here is a real "holds
            # nothing", not a parse failure, so it is kept as an empty
            # string rather than converted to None.
            held_mutexes = mx.group("val").strip()
            continue
        if line.startswith("  at ") or line.startswith("  native:") or "waiting on" in line \
           or line.strip().startswith("- locked") or line.strip().startswith("- waiting"):
            if len(frames) < max_frames:
                frames.append(line.strip())
        elif line.strip() == "" or line.startswith("DumpLatencyMs:"):
            # Blank line / DumpLatencyMs ends this thread's block.
            in_main = False

    flush()
    return out
