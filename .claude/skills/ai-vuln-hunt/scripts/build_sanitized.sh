#!/usr/bin/env bash
# build_sanitized.sh — produce an ASAN/UBSAN-INSTRUMENTED build of the target (or a hot unit),
# because LD_PRELOAD does NOT instrument an already-compiled .so. Two modes:
#
#   build_sanitized.sh bazel <bazel_target> [-- extra bazel args]
#       Builds //<target> with -fsanitize=address,undefined via a throwaway --config. Use when
#       the target is Bazel-built and you want the real native extension, sanitized. Slow but
#       faithful (no stubs) — the gold standard for native memory-safety PoCs.
#
#   build_sanitized.sh so <out.so> <unit1.cc> [unit2.cc ...] [-- -Icode/include ...]
#       Compiles specific translation unit(s) into a sanitized shared object (-shared -fPIC).
#       Faithful to those units' real code; only use when the suspect logic is self-contained.
#
# After building, verify with:  scripts/run_atheris.sh check-instrumented <out.so>
#
# BLACK-BOX NOTE: builds source under code/; touches no identity files.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:?usage: build_sanitized.sh {bazel <target>|so <out.so> <unit.cc>...} [-- args]}"; shift
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "${FINDINGS_DIR:-.}" --phase dast --actor build_sanitized.sh "$@" >/dev/null 2>&1 || true; }

case "$MODE" in
  bazel)
    TARGET="${1:?bazel target}"; shift || true
    EXTRA=(); seen=0; for a in "$@"; do [ "$a" = "--" ] && { seen=1; continue; }; [ "$seen" = 1 ] && EXTRA+=("$a"); done
    command -v bazel >/dev/null 2>&1 || command -v bazelisk >/dev/null 2>&1 || { echo "[san] bazel not installed" >&2; exit 1; }
    BZ="$(command -v bazel || command -v bazelisk)"
    echo "[san] bazel build $TARGET with ASAN/UBSAN (this can take a long time)" >&2
    led --kind tool_call --summary "bazel asan build: $TARGET"
    "$BZ" build "$TARGET" \
      --copt=-fsanitize=address --copt=-fsanitize=undefined --copt=-fno-omit-frame-pointer \
      --copt=-g --linkopt=-fsanitize=address --linkopt=-fsanitize=undefined \
      --strip=never --compilation_mode=dbg "${EXTRA[@]}" \
      || { echo "[san] bazel asan build failed (see output). Try a narrower target or 'so' mode." >&2; exit 1; }
    echo "[san] built. Artifacts under bazel-bin/. Point PYTHONPATH at the instrumented extension," >&2
    echo "[san] then: run_atheris.sh check-instrumented <module-or-.so>" >&2
    ;;
  so)
    OUT="${1:?out.so}"; shift
    UNITS=(); EXTRA=(); seen=0
    for a in "$@"; do if [ "$a" = "--" ]; then seen=1; continue; fi
      if [ "$seen" = 1 ]; then EXTRA+=("$a"); else UNITS+=("$a"); fi; done
    [ "${#UNITS[@]}" -ge 1 ] || { echo "[san] need >=1 unit.cc" >&2; exit 2; }
    CXX="${CXX:-clang++}"; command -v "$CXX" >/dev/null 2>&1 || CXX=g++
    command -v "$CXX" >/dev/null 2>&1 || { echo "[san] no C++ compiler" >&2; exit 1; }
    mkdir -p "$(dirname "$OUT")"
    echo "[san] $CXX $SAN -shared -fPIC ${UNITS[*]} -> $OUT" >&2
    led --kind tool_call --summary "sanitized .so build: $(basename "$OUT")"
    "$CXX" $SAN -shared -fPIC "${EXTRA[@]}" "${UNITS[@]}" -o "$OUT" \
      || { echo "[san] compile failed; the unit likely needs more of its real dependencies (-I / .cc)." >&2; exit 1; }
    if bash "$HERE/run_atheris.sh" check-instrumented "$OUT" >/dev/null 2>&1; then
      echo "[san] OK: $OUT is ASAN-instrumented" >&2
    else
      echo "[san] WARN: built $OUT but instrumentation marker not found (compiler may lack ASAN)" >&2
    fi
    ;;
  *) echo "usage: build_sanitized.sh {bazel <target>|so <out.so> <unit.cc>...} [-- args]" >&2; exit 2;;
esac
