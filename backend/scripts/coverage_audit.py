"""Reports which bugreport sections ParseCat can see and which it cannot.

Written after a real miss. A user asked whether their device had a GPS
problem; it did, and every number needed to prove it was sitting in
`dumpsys location`, which no parser read. The tool answered "no evidence
could be verified" -- technically true, practically a false negative, and
nothing about the output suggested a capability gap rather than a clean
device.

The lesson is that coverage has to be measured, not remembered. This
script enumerates every section actually present in real captures, marks
which ones the current build parses, and ranks the unparsed ones by size
so gaps surface as a list instead of as a wrong answer months later.

Size is a proxy for how much is in there, not for how much MATTERS -- a
tiny section can carry a decisive fact and a huge one can be noise. Treat
the ranking as a place to start reading, never as a priority order.

    python scripts/coverage_audit.py <capture.zip> [more.zip ...]
    python scripts/coverage_audit.py                # defaults to tests/fixtures
"""
from __future__ import annotations

import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.parsers import WANTED_SECTIONS  # noqa: E402
from app.parsers.section_extractor import (  # noqa: E402
    DUMPSYS_START_RE,
    LOG_SECTION_NAME_MAP,
    LOG_SECTION_START_RE,
    find_main_bugreport_entry,
)

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

# Sections that are genuinely not worth parsing, with the reason. Anything
# NOT listed here and not parsed is an open question, which is the point.
KNOWN_NOT_USEFUL = {
    "procstats": "long-window aggregate; batterystats and meminfo cover the same ground",
    "gfxinfo": "per-frame render timings; useful for jank work, not device triage",
    "dbinfo": "sqlite query stats; app-internal",
    "settings": "enormous key/value dump; specific keys are better fetched on demand",
}


def section_inventory(zip_path: Path) -> dict[str, int]:
    """Counts lines per section name, using the same delimiters the real
    extractor uses so this cannot drift from what the parser sees."""
    sizes: dict[str, int] = defaultdict(int)
    with zipfile.ZipFile(zip_path) as zf:
        entry = find_main_bugreport_entry(zf)
        with zf.open(entry) as raw:
            current = None
            for line_bytes in raw:
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                # End markers MUST be tested before start markers. A log
                # footer ("------ 0.060s was the duration of 'chmod debugfs'
                # ------") satisfies the start pattern too, and testing
                # starts first invents sections named after footers. The real
                # extractor is immune because it only opens a section whose
                # name is in WANTED_SECTIONS, but this inventory accepts
                # every name -- so it has to be stricter, not looser, than
                # the thing it is auditing.
                if re.match(r"^--------- .* was the duration of dumpsys ", line) or \
                   re.match(r"^------ .* was the duration of '", line):
                    current = None
                    continue
                m = DUMPSYS_START_RE.match(line)
                if m:
                    current = m.group(2)
                    continue
                m = LOG_SECTION_START_RE.match(line)
                if m:
                    name = m.group(1).strip()
                    current = LOG_SECTION_NAME_MAP.get(name, name.lower().replace(" ", "_"))
                    continue
                if current:
                    sizes[current] += 1
    return dict(sizes)


def main() -> int:
    paths = [Path(a) for a in sys.argv[1:]] or sorted(FIXTURES.glob("*.zip"))
    if not paths:
        print("No captures given and no fixtures found.")
        return 2

    merged: dict[str, int] = defaultdict(int)
    seen_in: dict[str, int] = defaultdict(int)
    for p in paths:
        print(f"scanning {p.name} ...")
        for name, size in section_inventory(p).items():
            merged[name] = max(merged[name], size)
            seen_in[name] += 1

    parsed = sorted(n for n in merged if n in WANTED_SECTIONS)
    unparsed = sorted((n for n in merged if n not in WANTED_SECTIONS),
                      key=lambda n: -merged[n])

    print()
    print(f"{len(merged)} distinct sections across {len(paths)} capture(s)")
    print(f"  parsed   : {len(parsed)}")
    print(f"  unparsed : {len(unparsed)}")
    print()
    print("PARSED")
    for n in parsed:
        print(f"  {merged[n]:>8,} lines  {n}  (in {seen_in[n]}/{len(paths)})")

    print()
    print("UNPARSED, largest first -- size is where to look, not what matters")
    for n in unparsed[:40]:
        note = KNOWN_NOT_USEFUL.get(n, "")
        flag = "  " if note else "??"
        print(f"{flag} {merged[n]:>8,} lines  {n}"
              f"  (in {seen_in[n]}/{len(paths)})"
              + (f"  -- {note}" if note else ""))

    open_gaps = [n for n in unparsed if n not in KNOWN_NOT_USEFUL]
    print()
    print(f"{len(open_gaps)} unparsed sections have no recorded reason for being skipped.")
    print("Each is a question ParseCat currently cannot answer at all, and will")
    print("answer with 'no evidence found' rather than 'I cannot see that'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
