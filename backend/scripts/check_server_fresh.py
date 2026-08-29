"""Fails loudly if the running ParseCat server is not the code on disk.

Run this before trusting any answer from a local server, and especially
before concluding that a capture contains no evidence of something.

Why this exists: during development a killed-but-still-listening server
served pre-parser code for several minutes. Every request succeeded, the
schema was current, and a real GPS problem came back as "no evidence of a
geolocation issue could be verified." Nothing looked wrong. A diagnosis
tool that silently answers "nothing found" from stale code is worse than
one that crashes, because a crash gets investigated.

    python scripts/check_server_fresh.py            # exit 0 = fresh
    PARSECAT_URL=http://host:8000 python scripts/check_server_fresh.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent / "app"


def disk_fingerprint() -> str:
    """Must stay byte-identical to main._source_fingerprint()."""
    h = hashlib.sha256()
    for path in sorted(APP_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        h.update(path.relative_to(APP_ROOT).as_posix().encode())
        h.update(path.read_bytes())
    return h.hexdigest()[:16]


def main() -> int:
    base = os.environ.get("PARSECAT_URL", "http://127.0.0.1:8000").rstrip("/")
    try:
        with urllib.request.urlopen(f"{base}/api/health", timeout=10) as resp:
            health = json.load(resp)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"FAIL  cannot reach {base}/api/health: {exc}")
        return 2

    served = health.get("source_fingerprint")
    local = disk_fingerprint()
    if served != local:
        print("FAIL  the running server is NOT the code on disk.")
        print(f"      server : {served}")
        print(f"      disk   : {local}")
        print(f"      started: {health.get('started_at')}")
        print()
        print("      Any 'no evidence found' answer from this server is unreliable.")
        print("      Restart it, and make sure no orphaned process still holds the")
        print("      port -- killing a --reload parent can leave its child serving.")
        return 1

    print(f"OK    server matches disk ({local})")
    print(f"      started at {health.get('started_at')}")
    print(f"      parses {len(health.get('parsed_sections', []))} sections: "
          f"{', '.join(health.get('parsed_sections', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
