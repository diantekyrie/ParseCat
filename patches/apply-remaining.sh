#!/bin/bash
set -euo pipefail
git fetch origin main
git show origin/main:frontend/src/App.jsx > frontend/src/App.jsx
git show origin/main:backend/app/services/reasoning.py > backend/app/services/reasoning.py
patch -p1 < patches/app-from-main.patch
patch -p1 < patches/reasoning-from-main.patch
python3 - <<'PY'
from pathlib import Path
app = Path("frontend/src/App.jsx").read_text()
reason = Path("backend/app/services/reasoning.py").read_text()
assert "timestampOrderMinutes" in app
assert "if (event.dated || at.dated) return delta <= windowMinutes" in app
assert "export default function App" in app
assert app.count("\n") > 1800
assert "DEVICE_CONTEXT_LLM_FIELDS" in reason
assert "def evidence_confidence" in reason
assert '"serial"' not in reason[reason.find("DEVICE_CONTEXT_LLM_FIELDS"):reason.find("DEVICE_CONTEXT_LLM_FIELDS")+800]
print("patched files look correct")
PY
