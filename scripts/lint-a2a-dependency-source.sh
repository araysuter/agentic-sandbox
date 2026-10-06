#!/usr/bin/env bash
# Keep the standalone fork build independent of the unused private A2A SDK.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 - <<'PYTHON'
import pathlib
import re
manifest = pathlib.Path("management/agentic-sandbox-executor/Cargo.toml").read_text()
lock = pathlib.Path("management/Cargo.lock").read_text()
if re.search(r"^a2a(?:_client|_server)?\s*=", manifest, re.M):
    raise SystemExit("A2A SDK dependencies require a new reviewed build decision")
if "git.integrolabs.net/roctinam/a2a-rs" in lock:
    raise SystemExit("Lockfile still requires the private A2A SDK mirror")
print("✓ lint-a2a-dependency-source: A2A wire adapter builds without private SDK access")
PYTHON
