#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
"${AIVH_PY:-python3}" poc.py; echo "exit=$?"
