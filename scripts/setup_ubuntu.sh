#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-9443}"

python3 main.py check

echo "Runtime OK."
echo "If a host firewall is enabled, allow TCP ${PORT}."
echo "If clients are outside your LAN, forward TCP ${PORT} on your router to this machine."
echo "No VPN package or Python package is installed by this script."
