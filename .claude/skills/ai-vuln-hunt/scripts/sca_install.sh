#!/usr/bin/env bash
# sca_install.sh — install SCA tools into ./.sca/bin (no root). All best-effort.
#
# Precedence per tool: existing binary -> go install -> release/install.sh -> pip --user.
# For air-gapped runs, pre-seed ./.sca/db and pass OFFLINE=1 to sca_scan.sh.
set -euo pipefail
BIN="$PWD/.sca/bin"; DB="$PWD/.sca/db"
mkdir -p "$BIN" "$DB"
export PATH="$BIN:$PATH" GOBIN="$BIN"
have(){ command -v "$1" >/dev/null 2>&1; }
echo "[sca-install] target=$BIN" >&2

# osv-scanner
if ! have osv-scanner; then
  go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null \
    || echo "[sca-install] osv-scanner: go install failed (need network/go)" >&2
fi
# syft + grype (official installers drop into $BIN)
if ! have syft; then
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] syft: installer failed" >&2
fi
if ! have grype; then
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] grype: installer failed" >&2
fi
# trivy
if ! have trivy; then
  curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] trivy: installer failed" >&2
fi
# python tools
python3 -m pip install --user --quiet pip-audit cyclonedx-bom 2>/dev/null \
  || echo "[sca-install] pip tools: pip install failed" >&2

# Warm offline OSV DB — this REQUIRES network (it downloads), so do NOT pass --offline here.
# The air-gapped scan later passes ONLY --offline against this pre-seeded DB. (gap: --offline and
# --download-offline-databases are contradictory in a single call.)
if have osv-scanner; then
  echo "[sca-install] warming offline OSV DB (needs network)…" >&2
  osv-scanner scan --download-offline-databases --recursive . >/dev/null 2>&1 \
    || osv-scanner --download-offline-databases -r . >/dev/null 2>&1 \
    || echo "[sca-install] offline DB warm failed (no network / flag drift) — online scan still works" >&2
fi
echo "[sca-install] done. PATH-prepend: export PATH=\"$BIN:\$PATH\"" >&2
