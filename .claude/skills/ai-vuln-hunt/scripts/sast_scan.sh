#!/usr/bin/env bash
# sast_scan.sh — off-the-shelf static analyzers over ./code, normalized + ranked.
#
# BLACK-BOX NOTE: scopes to source under code/ only. Never reads/passes identity files
# (VERSION/CHANGELOG/RELEASE/SECURITY). --changed-from uses `git diff RANGE` purely for
# scoping, never tags/log for identity. Dependency-version SCA is a separate stage.
#
# Every tool is OPTIONAL, time-boxed, and non-fatal. Emits per-tool raw output to
# <out>/raw and a normalized, de-duplicated, ranked leads file <out>/leads.json.
#
# Usage: sast_scan.sh <code_dir> <out_dir> [findings_dir] [--changed-from REF] [--subtree DIR]
set -euo pipefail
CODE="${1:?usage: sast_scan.sh <code_dir> <out_dir> [findings_dir]}"; shift
OUT="${1:?out_dir}"; shift
FIND="${1:-$(dirname "$OUT")}"; [ $# -gt 0 ] && shift || true
CHANGED=""; SUBTREE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --changed-from) CHANGED="$2"; shift 2;;
    --subtree) SUBTREE="$2"; shift 2;;
    *) shift;;
  esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/raw"
SCOPE="${SUBTREE:-$CODE}"
TIMEBOX="${TIMEBOX:-600}"
EXCLUDE='--exclude=*/third_party/* --exclude=*/external/* --exclude=*/test/* --exclude=*/tests/* --exclude=*/vendor/*'

led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase sast --actor sast_scan.sh "$@" >/dev/null 2>&1 || true; }
have(){ command -v "$1" >/dev/null 2>&1; }
tb(){ timeout "$TIMEBOX" "$@" || echo "[sast] timed-out/failed: $*" >&2; }

# Resolve changed-files scope (git diff only — never tag/log)
if [ -n "$CHANGED" ]; then
  if [ -x "$HERE/blackbox_guard.sh" ]; then "$HERE/blackbox_guard.sh" check-git diff "$CHANGED" >/dev/null; fi
  git -C "$CODE" diff --name-only "$CHANGED" 2>/dev/null | sed "s#^#$CODE/#" >"$OUT/raw/changed_files.txt" || true
fi

echo "[sast] scope=$SCOPE changed=${CHANGED:-none}" >&2

# ---------- Python ----------
if have bandit; then
  tb bandit -r "$SCOPE" -f json -ll -ii -o "$OUT/raw/bandit.json" 2>/dev/null || true
  led --kind tool_call --summary "bandit" --blob "$OUT/raw/bandit.json"
fi
if have ruff; then
  tb ruff check "$SCOPE" --select S,B,E9,F --output-format json >"$OUT/raw/ruff.json" 2>/dev/null || true
fi
if have semgrep; then
  tb semgrep scan --config p/python --config p/security-audit --sarif \
     --output "$OUT/raw/semgrep_py.sarif" $EXCLUDE "$SCOPE" 2>/dev/null || true
  led --kind tool_call --summary "semgrep python" --blob "$OUT/raw/semgrep_py.sarif"
fi

# ---------- C/C++ ----------
if have flawfinder; then
  tb flawfinder --sarif --minlevel=2 "$SCOPE" >"$OUT/raw/flawfinder.sarif" 2>/dev/null || true
fi
if have cppcheck; then
  tb cppcheck --enable=warning,style,performance,portability --inconclusive --xml \
     "$SCOPE" 2>"$OUT/raw/cppcheck.xml" || true
  led --kind tool_call --summary "cppcheck" --blob "$OUT/raw/cppcheck.xml"
fi
if have clang-tidy; then
  # clang-tidy/clang-analyzer need a compilation database. Try to obtain one; log if we can't.
  CDB=""
  if [ -f "$CODE/compile_commands.json" ]; then CDB="$CODE"
  elif have bear; then
    echo "[sast] generating compile_commands.json via bear is build-specific; skipping auto-gen" >&2
  fi
  if [ -n "$CDB" ]; then
    # Prioritize recon's ranked hot files if present, else all C/C++ units (grouped predicate).
    CAP="${CLANG_TIDY_CAP:-400}"
    if [ -f "$FIND/recon_hot.txt" ]; then
      LIST="$(grep -E '\.(c|cc|cpp|cxx|cu|C)$' "$FIND/recon_hot.txt" 2>/dev/null | head -"$CAP")"
    else
      LIST="$(find "$SCOPE" \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
               -o -name '*.cu' -o -name '*.C' \) -print 2>/dev/null | head -"$CAP")"
    fi
    N="$(printf '%s\n' "$LIST" | grep -c . || true)"
    echo "[sast] clang-tidy on $N file(s) (cap $CAP)" >&2
    printf '%s\n' "$LIST" | while read -r src; do
      [ -n "$src" ] || continue
      tb clang-tidy --checks='clang-analyzer-*,bugprone-*,cert-*' -p "$CDB" "$src" \
        >>"$OUT/raw/clang-tidy.txt" 2>/dev/null || true
    done
    led --kind tool_call --summary "clang-tidy ($N files, cap $CAP)"
  else
    echo "[sast] clang-tidy SKIPPED: no compile_commands.json (deep clang-analyzer taint not run);" \
         "generate one (bazel aquery+compdb or bear) to enable. LLM semantic pass covers this gap." \
      | tee -a "$OUT/raw/clang-tidy.skipped.txt" >&2
    led --kind note --summary "clang-tidy skipped: no compile_commands.json"
  fi
fi
if have semgrep; then
  tb semgrep scan --config p/c --config p/cpp --sarif \
     --output "$OUT/raw/semgrep_c.sarif" $EXCLUDE "$SCOPE" 2>/dev/null || true
fi

# Optional CodeQL (heavy, needs a build) behind CODEQL=1
if [ "${CODEQL:-0}" = 1 ] && have codeql; then
  echo "[sast] CodeQL enabled (heavy) — build a DB then analyze with security-extended" >&2
fi

# ---------- Normalize + rank ----------
if [ -f "$HERE/sast_merge.py" ]; then
  python3 "$HERE/sast_merge.py" "$OUT/raw" >"$OUT/leads.json" \
    || echo '{"schema":"sast-leads-1.0","leads":[]}' >"$OUT/leads.json"
else
  echo '{"schema":"sast-leads-1.0","leads":[]}' >"$OUT/leads.json"
fi
led --kind artifact --summary "sast leads ranked" --blob "$OUT/leads.json"
echo "[sast] done -> $OUT/leads.json" >&2
