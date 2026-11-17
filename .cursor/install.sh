#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"

export PATH="/usr/local/bin:${PATH:-}"

NODE_MIN=24
if ! command -v node >/dev/null || ! node -e "process.exit(Number(process.version.slice(1).split('.')[0])>=${NODE_MIN}?0:1)"; then
  NODE_VERSION=24.22.2
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
    | sudo tar -xJ -C /usr/local --strip-components=1 --no-same-owner
  export PATH="/usr/local/bin:${PATH:-}"
fi

if ! command -v python3.14 >/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends software-properties-common
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends python3.14 python3.14-venv
  sudo ln -sf /usr/bin/python3.14 /usr/local/bin/python3.14
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  python3.14 -m venv "$VENV"
fi
"$VENV/bin/pip" install --require-hashes -r requirements-dev.txt
npm ci
npx playwright install --with-deps chromium
"$VENV/bin/python" scripts/build_population.py --check
