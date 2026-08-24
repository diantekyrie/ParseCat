"""Parsers for Android memory state, from two different sources.

1. `DUMP OF SERVICE meminfo` -- a point-in-time snapshot of the whole
   system: how much RAM exists, how it's split (free/used/cached/lost),
   ZRAM/swap, and per-process RSS and PSS rankings. This is the "what did
   memory look like at capture time" picture.

2. `am_pss` events in the EVENT LOG -- repeated per-process samples taken
   over the life of the log. Because the same process is sampled more than
   once, these are the only source that can show memory CHANGING over
   time, which is what distinguishes "this app is big" from "this app got
   bigger."

Two real characteristics of the data, both load-bearing:

* **am_pss reports RSS, not PSS, on modern Android.** In a real Pixel
  capture all 244 am_pss events had pss/uss/swapPss set to 0 and only rss
  populated -- PSS collection is expensive and often skipped. The parsed
  fields are named for what they actually are, and a zero PSS is recorded
  as None (unknown/not collected) rather than as a real measurement of
  zero, so nothing downstream can report "0 KB PSS" as a finding.

* **am_pss values are in BYTES**; the dumpsys tables are in KILOBYTES.
  Everything here is normalized to KB so the two sources are comparable,
  and the field names say `_kb` so the unit is never ambiguous.

Growth is deliberately NOT interpreted here. A sequence like
146MB -> 556MB -> 560MB -> 504MB -> 504MB -> 533MB (a real one from the
test capture) is growth, but it is not monotonic and calling it a "leak"
would be an inference this data does not support. The samples are kept in
order so a caller can show the actual shape.
"""
from __future__ import annotations

import re

from app.parsers.base import (
    MemorySnapshot,
    ProcessMemorySample,
    ProcessMemoryUsage,
    SourceRef,
)
from app.parsers.section_extractor import Section

# "  1,377,160K: com.foo.bar (pid 4385)  (1,282,633K in swap)"
# "    332,637K: com.foo (pid 6609 / activities)(    1,533K in swap)"
# "    772,644K: system (pid 1731)"                 <- RSS table has no swap column
PROCESS_MEM_RE = re.compile(
    r"^\s*(?P<kb>[\d,]+)K:\s+(?P<process>.+?)\s+\(pid (?P<pid>\d+)"
    r"(?:\s*/\s*(?P<state>[^)]*))?\)"
    r"(?:\s*\(\s*(?P<swap>[\d,]+)K in swap\))?\s*$"
)

TOTAL_RAM_RE = re.compile(r"^\s*Total RAM:\s+(?P<kb>[\d,]+)K(?:\s*\(status (?P<status>[^)]*)\))?")
FREE_RAM_RE = re.compile(
    r"^\s*Free RAM:\s+(?P<kb>[\d,]+)K"
    r"(?:\s*\(\s*(?P<cached_pss>[\d,]+)K cached pss \+\s*(?P<cached_kernel>[\d,]+)K cached kernel"
    r"\s*\+\s*(?P<free>[\d,]+)K free\))?"
)
USED_RAM_RE = re.compile(
    r"^\s*Used RAM:\s+(?P<kb>[\d,]+)K"
    r"(?:\s*\(\s*(?P<used_pss>[\d,]+)K used pss \+\s*(?P<kernel>[\d,]+)K kernel\))?"
)
LOST_RAM_RE = re.compile(r"^\s*Lost RAM:\s+(?P<kb>[\d,]+)K")
ZRAM_RE = re.compile(
    r"^\s*ZRAM:\s+(?P<physical>[\d,]+)K physical used for\s+(?P<in_swap>[\d,]+)K in swap"
    r"(?:\s*\(\s*(?P<total_swap>[\d,]+)K total swap\))?"
)

# A summary table header like "Total PSS by process:" ends the previous one.
TABLE_HEADER_RE = re.compile(r"^(?P<label>Total (?:PSS|RSS) by [a-zA-Z ]+):\s*$")

# am_pss: [pid, uid, processName, pss, uss, swapPss, rss, statType, procState, timeToCollect]
AM_PSS_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\S+\s+\d+\s+\d+ "
    r"[VDIWEF] am_pss\s*:\s*\[(?P<body>.*)\]\s*$"
)


def _kb(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.replace(",", ""))
    except ValueError:
        return None


def _int_or_none(value: str) -> int | None:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def parse_meminfo(section: Section) -> MemorySnapshot | None:
    """Parses the summary tables at the end of `dumpsys meminfo`.

    The per-process MEMINFO blocks earlier in the section (15,000+ lines in
    a real capture) are deliberately skipped -- they're a detailed
    breakdown of every process's heap, and the summary tables at the end
    carry the same headline numbers in a form that's actually rankable.
    """
    ram: dict[str, int | None] = {}
    status: str | None = None
    tables: dict[str, list[ProcessMemoryUsage]] = {}
    current_table: str | None = None

    for i, raw in enumerate(section.lines):
        abs_line = section.line_start + i

        header = TABLE_HEADER_RE.match(raw)
        if header:
            current_table = header.group("label")
            tables.setdefault(current_table, [])
            continue

        if current_table:
            m = PROCESS_MEM_RE.match(raw)
            if m:
                # The "by OOM adjustment" table nests processes under a
                # category heading; both levels match this pattern, but the
                # nested rows are indented further. Only the flat per-process
                # tables are collected, so a category total is never mistaken
                # for a process.
                tables[current_table].append(ProcessMemoryUsage(
                    process=m.group("process").strip(),
                    pid=int(m.group("pid")),
                    memory_kb=_kb(m.group("kb")) or 0,
                    swap_kb=_kb(m.group("swap")),
                    state=(m.group("state") or "").strip() or None,
                    source_ref=SourceRef(section.name, abs_line, abs_line),
                ))
                continue
            if raw.strip() and not raw.startswith(" "):
                current_table = None  # a new unindented heading ends the table

        for key, regex in (
            ("total_ram_kb", TOTAL_RAM_RE), ("free_ram_kb", FREE_RAM_RE),
            ("used_ram_kb", USED_RAM_RE), ("lost_ram_kb", LOST_RAM_RE),
        ):
            m = regex.match(raw)
            if m:
                ram[key] = _kb(m.group("kb"))
                groups = m.groupdict()
                if key == "total_ram_kb":
                    status = groups.get("status")
                elif key == "free_ram_kb":
                    ram["cached_pss_kb"] = _kb(groups.get("cached_pss"))
                    ram["cached_kernel_kb"] = _kb(groups.get("cached_kernel"))
                    ram["truly_free_kb"] = _kb(groups.get("free"))
                elif key == "used_ram_kb":
                    ram["used_pss_kb"] = _kb(groups.get("used_pss"))
                    ram["kernel_kb"] = _kb(groups.get("kernel"))
                break

        z = ZRAM_RE.match(raw)
        if z:
            ram["zram_physical_kb"] = _kb(z.group("physical"))
            ram["zram_in_swap_kb"] = _kb(z.group("in_swap"))
            ram["total_swap_kb"] = _kb(z.group("total_swap"))

    if not ram and not tables:
        return None

    return MemorySnapshot(
        total_ram_kb=ram.get("total_ram_kb"),
        free_ram_kb=ram.get("free_ram_kb"),
        used_ram_kb=ram.get("used_ram_kb"),
        lost_ram_kb=ram.get("lost_ram_kb"),
        cached_pss_kb=ram.get("cached_pss_kb"),
        cached_kernel_kb=ram.get("cached_kernel_kb"),
        truly_free_kb=ram.get("truly_free_kb"),
        used_pss_kb=ram.get("used_pss_kb"),
        kernel_kb=ram.get("kernel_kb"),
        zram_physical_kb=ram.get("zram_physical_kb"),
        zram_in_swap_kb=ram.get("zram_in_swap_kb"),
        total_swap_kb=ram.get("total_swap_kb"),
        status=status,
        top_by_rss=tables.get("Total RSS by process", [])[:20],
        top_by_pss=tables.get("Total PSS by process", [])[:20],
        source_ref=SourceRef(section.name, section.line_start, section.line_end),
    )


def parse_memory_samples(section: Section) -> list[ProcessMemorySample]:
    """Parses `am_pss` events -- repeated per-process memory samples."""
    out: list[ProcessMemorySample] = []
    for i, raw in enumerate(section.lines):
        m = AM_PSS_RE.match(raw)
        if not m:
            continue
        f = m.group("body").split(",")
        if len(f) < 7:
            continue  # unexpected shape -- skipped rather than guessed at

        pid = _int_or_none(f[0])
        uid = _int_or_none(f[1])
        process = f[2].strip()
        # Values are bytes here; the dumpsys tables are KB. Normalize to KB
        # so both sources are directly comparable.
        pss_bytes = _int_or_none(f[3])
        rss_bytes = _int_or_none(f[6])
        swap_pss_bytes = _int_or_none(f[5])

        abs_line = section.line_start + i
        out.append(ProcessMemorySample(
            timestamp=m.group("ts"),
            pid=pid,
            uid=uid,
            process=process,
            package=process.split(":")[0] if process else None,
            # A zero PSS means "not collected on this build", not a real
            # measurement of zero -- recorded as unknown so nothing
            # downstream can report 0 KB as a finding.
            pss_kb=(pss_bytes // 1024) if pss_bytes else None,
            rss_kb=(rss_bytes // 1024) if rss_bytes else None,
            swap_pss_kb=(swap_pss_bytes // 1024) if swap_pss_bytes else None,
            proc_state=_int_or_none(f[8]) if len(f) > 8 else None,
            source_ref=SourceRef(section.name, abs_line, abs_line),
        ))
    return out
