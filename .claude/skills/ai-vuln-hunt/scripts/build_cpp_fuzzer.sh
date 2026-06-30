#!/usr/bin/env bash
# build_cpp_fuzzer.sh — compile a SINGLE translation unit + a libFuzzer harness with
# ASAN/UBSAN, WITHOUT a full Bazel build. Auto-generates weak link stubs from the
# linker's "undefined reference" errors in a loop until the unit links.
#
# BLACK-BOX NOTE: operates only on source paths under code/. No identity files involved.
#
# Usage: build_cpp_fuzzer.sh <harness.cc> <out_binary> <unit1.cc> [unit2.cc ...] \
#                            [-- extra clang args like -Icode/include]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${1:?usage: build_cpp_fuzzer.sh <harness.cc> <out_bin> <unit.cc>... [-- args]}"; shift
OUTBIN="${1:?out_binary}"; shift
UNITS=(); EXTRA=()
seen_dd=0
for a in "$@"; do
  if [ "$a" = "--" ]; then seen_dd=1; continue; fi
  if [ "$seen_dd" = 1 ]; then EXTRA+=("$a"); else UNITS+=("$a"); fi
done
FIND="${FINDINGS_DIR:-$(dirname "$OUTBIN")}"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase dast --actor build_cpp_fuzzer.sh "$@" >/dev/null 2>&1 || true; }

CXX="${CXX:-clang++}"
command -v "$CXX" >/dev/null 2>&1 || { echo "[build] $CXX not found; try gcc/clang install" >&2; exit 1; }
SAN="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1"
STUBS="$(mktemp --suffix=.cc)"; : > "$STUBS"
STUBBED_SYMS=()                          # names of every weak-stubbed symbol (provenance!)
WORK="$(dirname "$OUTBIN")"; mkdir -p "$WORK"

echo "[build] harness=$HARNESS units=${UNITS[*]} extra=${EXTRA[*]}" >&2
attempt=0; MAX=25
while :; do
  attempt=$((attempt+1))
  LOG="$WORK/link_attempt_${attempt}.log"
  if "$CXX" $SAN "${EXTRA[@]}" "$HARNESS" "${UNITS[@]}" "$STUBS" -o "$OUTBIN" 2>"$LOG"; then
    echo "[build] linked after $attempt attempt(s) -> $OUTBIN" >&2
    # Persist stub provenance: confirm_finding.sh requires no stubbed symbol on the taint path,
    # and forces re-confirmation on the real build before a stubbed PoC can be CONFIRMED.
    STUBS_JSON="$OUTBIN.stubs.json"
    printf '%s\n' "${STUBBED_SYMS[@]:-}" | jq -R . 2>/dev/null | jq -cs 'map(select(length>0))' \
      > "$STUBS_JSON" 2>/dev/null || echo '[]' > "$STUBS_JSON"
    n="$(jq 'length' "$STUBS_JSON" 2>/dev/null || echo 0)"
    if [ "$n" -gt 0 ]; then
      echo "[build] WARNING: linked with $n WEAK STUB(s): $STUBS_JSON" >&2
      echo "[build] A crash reached through a stub may be a build artifact, NOT a real bug." >&2
      echo "[build] In finding.json set stubbed_symbols from this file and needs_real_build_confirmation=true" >&2
      echo "[build] until you re-confirm the minimized input against the real (build_sanitized.sh bazel) build." >&2
    fi
    led --kind tool_call --summary "built libfuzzer harness ($attempt attempts, $n stubs)" --blob "$OUTBIN" || true
    led --kind artifact --summary "stub provenance" --blob "$STUBS_JSON" || true
    break
  fi
  # Extract undefined symbols and emit weak stubs.
  NEW="$(grep -oE 'undefined reference to .?[A-Za-z_][A-Za-z0-9_:]*' "$LOG" \
        | sed -E "s/.*to .?//" | tr -d \"\047\"\140 | sort -u || true)"
  if [ -z "$NEW" ]; then
    echo "[build] link failed and no resolvable undefined refs; see $LOG" >&2
    cat "$LOG" >&2; exit 1
  fi
  added=0
  while IFS= read -r sym; do
    [ -z "$sym" ] && continue
    grep -qF "/* STUB: $sym */" "$STUBS" 2>/dev/null && continue
    {
      echo "/* STUB: $sym */"
      echo "extern \"C\" __attribute__((weak)) void ${sym}() {}"
    } >> "$STUBS"
    STUBBED_SYMS+=("$sym")
    added=$((added+1))
  done <<< "$NEW"
  echo "[build] attempt $attempt: added $added stub(s)" >&2
  if [ "$attempt" -ge "$MAX" ]; then echo "[build] gave up after $MAX attempts" >&2; exit 1; fi
done

echo "[build] run: $OUTBIN -runs=200000 -max_total_time=120 corpus/" >&2
echo "[build] (set ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1)" >&2
