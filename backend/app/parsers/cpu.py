"""Parser for CPU load at capture time.

Two body shapes appear:

AOSP `dumpsys cpuinfo` (Pixel and Samsung bugreports observed):

    Load: 7.95 / 7.91 / 5.75
    CPU usage from 165681ms to 23595ms ago (2026-01-02 22:39:48.090 to 2026-01-02 22:42:10.176):
      98% 1234/kswapd0: 27% user + 70% kernel
    54% TOTAL: 19% user + 30% kernel + 1.5% iowait + 2.9% irq + 0.5% softirq

The TOTAL line is the aggregate. `kernel` is the same bucket as top(1)'s
`%sys`. Idle is not printed on that line. There is no `Threads: N total,
M running` line -- Samsung's `Threads in use: 0/32` is a dumpstate pool
counter, not process threads, so it is not mapped onto threads_total.
Process rows print pid and name but not tid, linux user, or a top(1)
state letter; those are required ProcessCpuUsage fields, so process rows
are left unmapped rather than filled with invented values.

A `top`-style snapshot is also accepted (existing synthetic fixture):

    Threads: 8422 total,   8 running, 8414 sleeping,   0 stopped,   0 zombie
      Mem:    11563M total,    11267M used,      296M free,        2M buffers
     Swap:     5781M total,     4937M used,      844M free,     1364M cached
    800%cpu  66%user   0%nice 190%sys 503%idle  15%iow  18%irq   8%sirq   0%host
      PID   TID USER         PR  NI[%CPU]S VIRT  RES PCY CMD             NAME
    16272 16272 shell         0 -20 57.3 R  10G  11M  fg top             top

This is a single point-in-time reading, not a time series -- it says what
was busy right when the bugreport ran, and nothing about a window before
or after. It cannot show a CPU spike that happened five minutes earlier;
only kernel_log or batterystats carry anything time-resolved for load.

The aggregate "%cpu" line's total can exceed 100% on a multi-core device
(800%cpu means up to 8 cores fully busy) -- it is kept exactly as printed
rather than normalized, since normalizing would need the core count and
this dump doesn't state it. AOSP TOTAL percents are typically 0-100+ and
are also kept as printed.
"""
from __future__ import annotations

import re

from app.parsers.base import CpuLoadSnapshot, ProcessCpuUsage, SourceRef
from app.parsers.section_extractor import Section

THREADS_RE = re.compile(
    r"^Threads:\s*(?P<total>\d+) total,\s*(?P<running>\d+) running"
)
AGGREGATE_RE = re.compile(
    r"^(?P<total>\d+)%cpu\s+(?P<user>\d+)%user\s+(?P<nice>\d+)%nice\s+"
    r"(?P<sys>\d+)%sys\s+(?P<idle>\d+)%idle\s+(?P<iow>\d+)%iow\s+"
    r"(?P<irq>\d+)%irq\s+(?P<sirq>\d+)%sirq"
)
PROCESS_ROW_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<user>\S+)\s+\S+\s+\S+\s+"
    r"(?P<cpu>[\d.]+)\s+(?P<state>\S)\s+\S+\s+\S+\s+\S+\s+(?P<cmd>\S+)\s+(?P<name>.+)$"
)

# AOSP dumpsys cpuinfo: "54% TOTAL: 19% user + 30% kernel + 1.5% iowait + ..."
DUMPSYS_TOTAL_RE = re.compile(r"^(?P<total>\d+(?:\.\d+)?)%\s+TOTAL:")
DUMPSYS_TOTAL_PART_RE = re.compile(
    r"(\d+(?:\.\d+)?)%\s+(user|kernel|iowait|irq|softirq)\b"
)
DUMPSYS_KERNEL_TO_AGG = {
    "user": "user",
    "kernel": "sys",
    "iowait": "iow",
    "irq": "irq",
    "softirq": "sirq",
}


def parse_cpu_snapshot(section: Section, top_n: int = 15) -> CpuLoadSnapshot | None:
    threads_total = threads_running = None
    agg: dict[str, float] = {}
    processes: list[ProcessCpuUsage] = []

    for i, raw in enumerate(section.lines):
        tm = THREADS_RE.match(raw)
        if tm:
            threads_total, threads_running = int(tm.group("total")), int(tm.group("running"))
            continue
        am = AGGREGATE_RE.match(raw)
        if am and not agg:
            agg = {k: float(v) for k, v in am.groupdict().items()}
            continue
        dm = DUMPSYS_TOTAL_RE.match(raw)
        if dm and not agg:
            agg = {"total": float(dm.group("total"))}
            for value, label in DUMPSYS_TOTAL_PART_RE.findall(raw):
                key = DUMPSYS_KERNEL_TO_AGG.get(label)
                if key:
                    agg[key] = float(value)
            continue
        pm = PROCESS_ROW_RE.match(raw)
        if pm:
            abs_line = section.line_start + i
            processes.append(ProcessCpuUsage(
                pid=int(pm.group("pid")), tid=int(pm.group("tid")), user=pm.group("user"),
                cpu_pct=float(pm.group("cpu")), state=pm.group("state"),
                command=pm.group("name").strip(),
                source_ref=SourceRef(section.name, abs_line, abs_line),
            ))

    if threads_total is None and not agg and not processes:
        return None

    processes.sort(key=lambda p: -p.cpu_pct)
    return CpuLoadSnapshot(
        total_pct=agg.get("total"), user_pct=agg.get("user"), sys_pct=agg.get("sys"),
        idle_pct=agg.get("idle"), iowait_pct=agg.get("iow"), irq_pct=agg.get("irq"),
        softirq_pct=agg.get("sirq"),
        threads_total=threads_total, threads_running=threads_running,
        top_processes=processes[:top_n],
        source_ref=SourceRef(section.name, section.line_start, section.line_end),
    )
