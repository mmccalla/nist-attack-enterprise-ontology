#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="/usr/local/bin:${HOME}/.local/bin:${PATH:-}"
PORT="${PORT:-8080}"

if ! ss -tln | grep -q ":${PORT} "; then
  PY="$ROOT/.venv/bin/python"
  [[ -x "$PY" ]] || PY=python3.14
  exec "$PY" -m http.server "$PORT" --bind 0.0.0.0 --directory "$ROOT"
fi
