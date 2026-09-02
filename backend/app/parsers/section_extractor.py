"""Streams the (typically 100-250MB) flattened bugreport .txt out of the zip
and slices out only the sections we have parsers for.

We never load the whole bugreport into memory. Two different delimiter
styles appear in a bugreport, and both are handled here:

`dumpsys` output:
    DUMP OF SERVICE [CRITICAL|HIGH] <name>:
    ...content...
    --------- 0.002s was the duration of dumpsys <name>, ending at: <ts>
    -------------------------------------------------------------------------------

Captured command/log output (logcat buffers, iptables, etc.):
    ------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------
    ...content...
    ------ 0.326s was the duration of 'SYSTEM LOG' ------

The same section name can appear multiple times (a fast CRITICAL/HIGH pass
early in the bugreport, then the full dump later) -- when that happens we
keep the LAST occurrence, since in every real bugreport observed the later,
un-prioritized dump is the complete one.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

DUMPSYS_START_RE = re.compile(r"^DUMP OF SERVICE(?: (CRITICAL|HIGH))? ([\w./+\-]+):\s*$")
DUMPSYS_END_RE = re.compile(r"^--------- .* was the duration of dumpsys ")

LOG_SECTION_START_RE = re.compile(r"^------ ([\w .'\-]+?)(?: \(.*\))? ------\s*$")
LOG_SECTION_END_RE = re.compile(r"^------ .* was the duration of '(.+?)' ------\s*$")

# Canonical names we use for log sections, mapped from their bugreport
# display name (case/spacing as printed) to the lowercase key we key
# results/parsers by, matching the "audio"/"package"/etc. convention used
# for dumpsys sections.
LOG_SECTION_NAME_MAP = {"SYSTEM LOG": "system_log", "SYSTEM PROPERTIES": "system_properties"}

# Pseudo-section name for the plain-text header block before the first
# delimited section (Build/Build fingerprint/Bootloader/Uptime/etc.) -- it
# has no delimiter of its own, it just ends where the first real section
# starts.
PREAMBLE = "preamble"



@dataclass
class Section:
    name: str
    priority: str | None     # None | "CRITICAL" | "HIGH" (dumpsys sections only)
    line_start: int          # first line of content (after the header line)
    line_end: int            # last line of content (inclusive, before the footer)
    lines: list[str] = field(default_factory=list)
    kind: str = "dumpsys"    # "dumpsys" | "log" -- which delimiter style bounded it


def find_main_bugreport_entry(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    """The flattened bugreport txt is a top-level `.txt` entry.

    Its FILENAME is not portable across OEMs even though its CONTENT format
    is -- `dumpstate` itself is AOSP code and every real capture seen (Pixel
    and Samsung) uses the identical "DUMP OF SERVICE ..." / "------ ... ------"
    delimiters, but which wrapper renames the output file differs. Pixel/
    stock AOSP names it `bugreport-<device>-<build>-<date>.txt`; a real
    Samsung One UI capture (BP4A.251205.006) instead named it
    `dumpstate-<date>.txt` -- same content, different name, and matching
    only the Pixel pattern raised "No top-level bugreport-*.txt entry found"
    on an otherwise perfectly parseable file.

    Rather than grow a per-OEM prefix whitelist that the next unseen device
    would just fail again, this picks the largest top-level `.txt` entry
    outright. In every real capture seen the flattened report dwarfs its
    top-level siblings by two to three orders of magnitude (174MB vs 238KB
    for Samsung's own `dumpstate_board.txt` and 19KB for `dumpstate_log.txt`
    in that same capture) -- size alone is a reliable, OEM-agnostic signal,
    and it costs nothing that a name-based check couldn't also provide.
    """
    candidates = [
        info for info in zf.infolist()
        if "/" not in info.filename and info.filename.endswith(".txt")
    ]
    if not candidates:
        raise ValueError("No top-level .txt entry found in zip")
    return max(candidates, key=lambda i: i.file_size)


def extract_sections_from_stream(text_stream, wanted_names: set[str]) -> dict[str, Section]:
    """Stream flattened bugreport text once, returning wanted sections."""
    results: dict[str, Section] = {}

    current: Section | None = None
    if PREAMBLE in wanted_names:
        current = Section(name=PREAMBLE, priority=None, line_start=1, line_end=1, kind="log")
    line_no = 0

    for line in text_stream:
        line_no += 1
        stripped = line.rstrip("\n").rstrip("\r")

        # The preamble has no delimiter of its own -- it ends the moment
        # ANY section header line appears (wanted or not), and that same
        # line is then re-examined below as a normal potential section
        # start.
        if current is not None and current.name == PREAMBLE:
            if DUMPSYS_START_RE.match(stripped) or LOG_SECTION_START_RE.match(stripped):
                current.line_end = line_no - 1
                results[PREAMBLE] = current
                current = None
            else:
                current.lines.append(stripped)
                continue

        if current is None:
            m = DUMPSYS_START_RE.match(stripped)
            if m and m.group(2) in wanted_names:
                current = Section(
                    name=m.group(2),
                    priority=m.group(1),
                    line_start=line_no + 1,
                    line_end=line_no + 1,
                    kind="dumpsys",
                )
                continue

            m2 = LOG_SECTION_START_RE.match(stripped)
            if m2:
                mapped = LOG_SECTION_NAME_MAP.get(m2.group(1), m2.group(1).lower().replace(" ", "_"))
                if mapped in wanted_names:
                    current = Section(
                        name=mapped,
                        priority=None,
                        line_start=line_no + 1,
                        line_end=line_no + 1,
                        kind="log",
                    )
            continue

        # We are inside a wanted section; watch for its end marker.
        end_matched = (
            DUMPSYS_END_RE.match(stripped) if current.kind == "dumpsys"
            else LOG_SECTION_END_RE.match(stripped)
        )
        if end_matched:
            current.line_end = line_no - 1
            if current.kind == "dumpsys":
                # Keep the LAST occurrence: a fast CRITICAL/HIGH pass
                # prints early, the full un-prioritized dump later.
                results[current.name] = current
            elif current.name not in results:
                # Keep the FIRST occurrence for log-style sections. A
                # bugreport can print a second, heavily time-filtered
                # "SYSTEM LOG" near the very end (e.g. a `-T <recent
                # timestamp>` trailer covering only the last few
                # seconds) reusing the same section name -- that's a
                # small subset, not a fuller version, so overwriting
                # with it would silently drop the real data.
                results[current.name] = current
            current = None
            continue

        current.lines.append(stripped)

    if current is not None:
        # File ended mid-section (shouldn't happen in a well-formed bugreport).
        current.line_end = line_no
        results[current.name] = current

    return results


def extract_sections_from_text(text: str, wanted_names: set[str]) -> dict[str, Section]:
    return extract_sections_from_stream(io.StringIO(text), wanted_names)


def extract_sections(zf: zipfile.ZipFile, wanted_names: set[str]) -> dict[str, Section]:
    """Stream the main bugreport txt once, returning the last occurrence of
    each wanted DUMP OF SERVICE section.
    """
    entry = find_main_bugreport_entry(zf)
    with zf.open(entry) as raw:
        # newline="\n": split ONLY on '\n', matching how every other tool
        # (grep, the line numbers cited in a hand-inspected bugreport, etc.)
        # counts lines. Universal-newlines mode (the default) also treats a
        # bare '\r' as a line break, and bugreports embed plenty of stray
        # '\r' bytes from native crash/tombstone dumps -- that silently
        # drifts every subsequent line number and misattributes citations.
        text_stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="\n")
        return extract_sections_from_stream(text_stream, wanted_names)
