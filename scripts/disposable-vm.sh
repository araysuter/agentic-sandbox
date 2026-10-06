#!/usr/bin/env bash
# Trusted host entry point. Never source repository shell or profile code.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$script_dir/disposable-runtime.py" "$@"
