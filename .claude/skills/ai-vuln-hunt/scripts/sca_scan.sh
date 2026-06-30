#!/usr/bin/env bash
# sca_scan.sh — Software Composition Analysis over ./code.
#
# BLACK-BOX NOTE: SCA inspects DEPENDENCIES (third-party component+version), never the
# host project's identity. It reads dependency manifests and a dependency's OWN embedded
# version markers only. It never reads the target's VERSION/CHANGELOG/RELEASE/SECURITY,
# never feeds the project NAME to any "known-CVE-by-project" lookup. OSV/NVD matching keys
# on (component, version) via purl — standard automated SCA, no target identity leaked.
#
# Builds an SBOM (syft) and matches dependency versions against OSV/GHSA/NVD
# (osv-scanner, grype, pip-audit, trivy). Every tool is OPTIONAL and non-fatal.
# Set OFFLINE=1 to use pre-seeded ./.sca/db OSV databases.
#
# Usage: sca_scan.sh <code_dir> <out_dir> [findings_dir]
set -euo pipefail

CODE="${1:?usage: sca_scan.sh <code_dir> <out_dir> [findings_dir]}"
OUT="${2:?usage: sca_scan.sh <code_dir> <out_dir> [findings_dir]}"
FIND="${3:-$(dirname "$OUT")}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/sbom" "$OUT/raw"
export PATH="$PWD/.sca/bin:$PATH"

led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase sca --actor sca_scan.sh "$@" >/dev/null 2>&1 || true; }
have(){ command -v "$1" >/dev/null 2>&1; }
run(){ echo "+ $*" >&2; "$@"; }

OFFLINE="${OFFLINE:-0}"
echo "[sca] code=$CODE out=$OUT offline=$OFFLINE" >&2

# ---- SBOM ----
if have syft; then
  run syft scan "dir:$CODE" -o "cyclonedx-json=$OUT/sbom/sbom.cyclonedx.json" \
      -o "spdx-json=$OUT/sbom/sbom.spdx.json" 2>"$OUT/raw/syft.log" || echo "[sca] syft failed" >&2
  led --kind tool_call --summary "syft SBOM" --blob "$OUT/sbom/sbom.cyclonedx.json"
else echo "[sca] syft absent (run sca_install.sh)" >&2; fi

if have trivy; then
  run trivy fs --format cyclonedx --output "$OUT/sbom/sbom.trivy.cyclonedx.json" "$CODE" \
      2>"$OUT/raw/trivy_sbom.log" || true
fi

# Python-specific SBOM if cyclonedx-py present
for req in "$CODE"/requirements*.txt "$CODE"/*/requirements*.txt; do
  [ -f "$req" ] || continue
  if python3 -m cyclonedx_py --help >/dev/null 2>&1; then
    python3 -m cyclonedx_py requirements "$req" -o "$OUT/sbom/py.$(basename "$req").cdx.json" 2>/dev/null || true
  fi
done

# ---- Vuln matching ----
# OFFLINE=1 uses ONLY --offline against a pre-seeded DB (warmed once, online, by sca_install.sh).
# Never combine --offline with --download-offline-databases (contradictory). osv-scanner flag/
# subcommand names drift across versions, so probe --help and pick a form that exists.
if have osv-scanner; then
  OSV_VER="$(osv-scanner --version 2>&1 | head -1 || echo unknown)"
  HELP="$(osv-scanner scan --help 2>&1 || osv-scanner --help 2>&1 || true)"
  OSV_ARGS=(scan); printf '%s' "$HELP" | grep -q -- '--recursive' && OSV_ARGS+=(--recursive) || OSV_ARGS+=(-r)
  if [ "$OFFLINE" = 1 ]; then
    if printf '%s' "$HELP" | grep -q -- '--offline'; then OSV_ARGS+=(--offline)
    else echo "[sca] this osv-scanner lacks --offline; running online" >&2; fi
  fi
  OSV_ARGS+=(--format=json)
  echo "[sca] osv-scanner=$OSV_VER args=${OSV_ARGS[*]} offline=$OFFLINE" >&2
  if ! run osv-scanner "${OSV_ARGS[@]}" "$CODE" >"$OUT/raw/osv.json" 2>"$OUT/raw/osv.log"; then
    # fallback to the bare-flag form for older/newer binaries
    run osv-scanner --format=json -r "$CODE" >"$OUT/raw/osv.json" 2>>"$OUT/raw/osv.log" || true
  fi
  if [ -f "$OUT/sbom/sbom.cyclonedx.json" ]; then
    run osv-scanner scan --format=json --sbom="$OUT/sbom/sbom.cyclonedx.json" \
        >"$OUT/raw/osv_sbom.json" 2>>"$OUT/raw/osv.log" || true
  fi
  led --kind tool_call --summary "osv-scanner ($OSV_VER) args=${OSV_ARGS[*]}" --blob "$OUT/raw/osv.json"
else echo "[sca] osv-scanner absent" >&2; fi

if have grype && [ -f "$OUT/sbom/sbom.cyclonedx.json" ]; then
  run grype "sbom:$OUT/sbom/sbom.cyclonedx.json" -o json >"$OUT/raw/grype.json" 2>"$OUT/raw/grype.log" || true
  led --kind tool_call --summary "grype" --blob "$OUT/raw/grype.json"
fi

if have trivy; then
  run trivy fs --scanners vuln --format json --output "$OUT/raw/trivy.json" "$CODE" 2>>"$OUT/raw/trivy_sbom.log" || true
fi

for req in "$CODE"/requirements*.txt "$CODE"/*/requirements*.txt; do
  [ -f "$req" ] || continue
  if have pip-audit; then
    run pip-audit -r "$req" --format json >"$OUT/raw/pip-audit.$(basename "$req").json" 2>/dev/null || true
  fi
done

# ---- Vendored C/C++ fingerprinting (no manifest) ----
if [ -x "$HERE/sca_fingerprint.sh" ]; then
  "$HERE/sca_fingerprint.sh" "$CODE" >"$OUT/raw/vendored.json" 2>/dev/null || echo '[]' >"$OUT/raw/vendored.json"
else
  echo '[]' >"$OUT/raw/vendored.json"
fi

# ---- Normalize ----
if [ -f "$HERE/sca_normalize.py" ]; then
  python3 "$HERE/sca_normalize.py" "$OUT/raw" "$OUT/raw/vendored.json" >"$OUT/findings.json" \
    || echo '{"schema_version":"sca-1.0","findings":[],"vendored_unidentified":[]}' >"$OUT/findings.json"
else
  echo '{"schema_version":"sca-1.0","findings":[],"vendored_unidentified":[]}' >"$OUT/findings.json"
fi
led --kind artifact --summary "sca findings normalized" --blob "$OUT/findings.json"
echo "[sca] done -> $OUT/findings.json" >&2
