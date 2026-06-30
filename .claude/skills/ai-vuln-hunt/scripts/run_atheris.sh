#!/usr/bin/env bash
# run_atheris.sh — run a Python Atheris harness with native sanitizers wired correctly.
#
# CRITICAL TRUTH about native coverage: LD_PRELOAD'ing the ASAN runtime does NOT instrument an
# already-compiled .so. ASAN only detects corruption in code compiled with -fsanitize=address.
# Against a stock prebuilt native extension, preload catches almost nothing (a few interceptable
# libc calls). To get real native memory-safety proofs you MUST load an INSTRUMENTED build of the
# target — rebuild it with scripts/build_sanitized.sh (bazel --config=asan, or a single sanitized
# .so) and point PYTHONPATH at it. This script verifies instrumentation and refuses to *claim*
# native coverage on an uninstrumented module.
#
# Subcommand:  run_atheris.sh check-instrumented <module-or-.so>   # exit 0 if ASAN-instrumented
#
# BLACK-BOX NOTE: only runs the AI-generated harness against code/; no identity files.
#
# Usage: run_atheris.sh <harness.py> [--time SECONDS] [--corpus DIR]
#                       [--require-instrumented <module-or-.so>] [-- atheris/libfuzzer args]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# Does a shared object / importable module contain ASAN instrumentation?
so_is_instrumented() { # $1 = path to .so
  local so="$1"; [ -f "$so" ] || return 2
  if command -v nm >/dev/null 2>&1; then nm -D "$so" 2>/dev/null | grep -q '__asan_init' && return 0; fi
  if command -v objdump >/dev/null 2>&1; then objdump -T "$so" 2>/dev/null | grep -q '__asan' && return 0; fi
  command -v strings >/dev/null 2>&1 && strings "$so" 2>/dev/null | grep -q '__asan_init' && return 0
  return 1
}
module_so_path() { # $1 = python module name -> prints .so path
  python3 - "$1" <<'PY' 2>/dev/null || true
import importlib.util,sys
s=importlib.util.find_spec(sys.argv[1])
print(s.origin if s and s.origin else "")
PY
}

if [ "${1:-}" = "check-instrumented" ]; then
  arg="${2:?usage: run_atheris.sh check-instrumented <module-or-.so>}"
  so="$arg"; case "$arg" in *.so) :;; *) so="$(module_so_path "$arg")";; esac
  if [ -z "$so" ] || [ ! -f "$so" ]; then echo "[atheris] cannot locate .so for '$arg'" >&2; exit 2; fi
  if so_is_instrumented "$so"; then echo "INSTRUMENTED: $so"; exit 0
  else echo "NOT-INSTRUMENTED: $so (rebuild with scripts/build_sanitized.sh)" >&2; exit 1; fi
fi

HARNESS="${1:?usage: run_atheris.sh <harness.py> [--time N] [--corpus DIR]}"; shift
TIME=120; CORPUS=""; REQUIRE_INSTR=""; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --time) TIME="$2"; shift 2;;
    --corpus) CORPUS="$2"; shift 2;;
    --require-instrumented) REQUIRE_INSTR="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    *) EXTRA+=("$1"); shift;;
  esac
done
FIND="${FINDINGS_DIR:-$(dirname "$HARNESS")}"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase dast --actor run_atheris.sh "$@" >/dev/null 2>&1 || true; }

command -v python3 >/dev/null 2>&1 || { echo "[atheris] python3 missing" >&2; exit 1; }
python3 -c 'import atheris' 2>/dev/null || { echo "[atheris] atheris not installed (pip install atheris)" >&2; exit 1; }

# Locate the clang ASAN runtime for LD_PRELOAD.
ASAN_RT=""
if command -v clang >/dev/null 2>&1; then
  ASAN_RT="$(clang -print-file-name=libclang_rt.asan-x86_64.so 2>/dev/null || true)"
fi
[ -f "$ASAN_RT" ] || ASAN_RT="$(ls /usr/lib*/clang/*/lib/linux/libclang_rt.asan-x86_64.so 2>/dev/null | head -1 || true)"

# Refuse to claim native memory-safety coverage on an uninstrumented target.
NATIVE_COVERAGE="none"
if [ -n "$REQUIRE_INSTR" ]; then
  so="$REQUIRE_INSTR"; case "$REQUIRE_INSTR" in *.so) :;; *) so="$(module_so_path "$REQUIRE_INSTR")";; esac
  if so_is_instrumented "$so"; then
    NATIVE_COVERAGE="asan-instrumented"; echo "[atheris] native coverage OK: $so is ASAN-instrumented" >&2
  else
    echo "[atheris] FATAL: --require-instrumented '$REQUIRE_INSTR' resolves to '$so' which is NOT ASAN-instrumented." >&2
    echo "[atheris] LD_PRELOAD alone will NOT catch memory bugs in it. Rebuild via scripts/build_sanitized.sh." >&2
    led --kind decision --summary "aborted: target not ASAN-instrumented (no real native coverage)"
    exit 3
  fi
else
  echo "[atheris] WARN: no --require-instrumented given. LD_PRELOAD catches NOTHING in an" >&2
  echo "[atheris] already-compiled .so. Use this for crash/contract oracles in pure-Python or" >&2
  echo "[atheris] sanitizer-built targets; for native memory bugs pass --require-instrumented." >&2
fi

export ASAN_OPTIONS="abort_on_error=1:handle_abort=1:detect_leaks=0:halt_on_error=1:symbolize=1:detect_odr_violation=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer 2>/dev/null || true)"

ART="$(dirname "$HARNESS")/artifacts"; mkdir -p "$ART"
LOG="$ART/atheris_$(date +%s).log"
ARGS=(-runs=2000000 -max_total_time="$TIME" -artifact_prefix="$ART/" "$ART/crash-")
[ -n "$CORPUS" ] && ARGS+=("$CORPUS")
[ ${#EXTRA[@]} -gt 0 ] && ARGS+=("${EXTRA[@]}")

echo "[atheris] preload=${ASAN_RT:-none} native_coverage=$NATIVE_COVERAGE time=${TIME}s" >&2
led --kind tool_call --summary "atheris run start: $(basename "$HARNESS") native_coverage=$NATIVE_COVERAGE"
set +e
if [ -n "$ASAN_RT" ]; then
  LD_PRELOAD="$ASAN_RT" python3 "$HARNESS" "${ARGS[@]}" 2>&1 | tee "$LOG"
else
  python3 "$HARNESS" "${ARGS[@]}" 2>&1 | tee "$LOG"
fi
rc=${PIPESTATUS[0]}
set -e
echo "[atheris] exit=$rc log=$LOG" >&2
led --kind artifact --summary "atheris run log (exit $rc)" --blob "$LOG"
# Hand crashing inputs to triage.
for c in "$ART"/crash-*; do
  [ -f "$c" ] || continue
  echo "[atheris] crash input: $c" >&2
done
exit 0
