#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -v
python3 -m py_compile api/gateway_api.py examples/demo_app.py
bash -n scripts/prepare-host.sh scripts/connect-client.sh
sh -n scripts/vpn-firewall.sh
if command -v docker >/dev/null; then
  SERVER_ENDPOINT=1.2.3.4 API_TOKEN=test-token-0123456789 docker compose config --quiet
fi
