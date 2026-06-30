#!/usr/bin/env bash
# triage_crash.sh — classify a crash/oracle log, compute a refactor-stable stack_hash
# for dedup, and (optionally) minimize the crashing input.
#
# Recognizes: ASAN/UBSAN/MSAN reports, SIGSEGV/SIGFPE/SIGABRT, CHECK/assert/abort,
# uncaught Python exceptions, and Python-oracle / differential-test violations.
# No oracle match => evidence_type "none" and the finding stays UNCONFIRMED.
#
# Usage: triage_crash.sh <log_file> [--input CRASH_INPUT] [--binary BIN] [--minimize]
# Prints a JSON triage object to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${1:?usage: triage_crash.sh <log_file> [--input F] [--binary B] [--minimize]}"; shift
INPUT=""; BIN=""; MIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --input) INPUT="$2"; shift 2;;
    --binary) BIN="$2"; shift 2;;
    --minimize) MIN=1; shift;;
    *) shift;;
  esac
done
command -v jq >/dev/null 2>&1 || { echo '{"error":"jq required"}'; exit 2; }
[ -f "$LOG" ] || { echo "{\"error\":\"no log: $LOG\"}"; exit 2; }
TXT="$(cat "$LOG")"

evidence="none"; sink="other"; cwe=""; severity="UNKNOWN"; signature=""
match(){ printf '%s' "$TXT" | grep -Eiq "$1"; }

if match 'ERROR: AddressSanitizer: heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow'; then
  evidence="asan"; sink="oob_rw"; cwe="CWE-787/125"; severity="HIGH"; signature="asan-buffer-overflow"
elif match 'AddressSanitizer: heap-use-after-free'; then
  evidence="asan"; sink="use_after_free"; cwe="CWE-416"; severity="HIGH"; signature="asan-uaf"
elif match 'AddressSanitizer'; then
  evidence="asan"; sink="memory"; cwe="CWE-119"; severity="HIGH"; signature="asan-other"
elif match 'runtime error:.*signed integer overflow|runtime error:.*shift'; then
  evidence="ubsan"; sink="int_overflow"; cwe="CWE-190"; severity="MEDIUM"; signature="ubsan-int-overflow"
elif match 'UndefinedBehaviorSanitizer|runtime error:'; then
  evidence="ubsan"; sink="undefined_behavior"; cwe="CWE-758"; severity="MEDIUM"; signature="ubsan-other"
elif match 'MemorySanitizer: use-of-uninitialized'; then
  evidence="msan"; sink="uninit"; cwe="CWE-457"; severity="MEDIUM"; signature="msan-uninit"
elif match 'SIGSEGV|Segmentation fault'; then
  evidence="signal_segv"; sink="oob_rw"; cwe="CWE-476/787"; severity="HIGH"; signature="signal_segv"
elif match 'SIGFPE|Floating point exception|division by zero'; then
  evidence="signal_fpe"; sink="availability"; cwe="CWE-369"; severity="MEDIUM"; signature="signal_fpe"
elif match 'SIGABRT|Aborted|abort\(\)|terminate called'; then
  evidence="abort"; sink="availability"; cwe="CWE-617"; severity="MEDIUM"; signature="abort"
elif match 'Check failed:|CHECK_|F[0-9].* Check failed|assert(ion)? .*failed'; then
  evidence="check_assert"; sink="availability"; cwe="CWE-617"; severity="MEDIUM"; signature="check_assert"
elif match 'DIFFERENTIAL-MISMATCH'; then
  evidence="differential_mismatch"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="differential_mismatch"
elif match 'METAMORPHIC-VIOLATION'; then
  evidence="metamorphic_violation"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="metamorphic_violation"
elif match 'INVARIANT-VIOLATION|ORACLE-VIOLATION'; then
  evidence="invariant_violation"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="invariant_violation"
elif match 'Traceback \(most recent call last\)'; then
  # Uncaught Python exception — only counts if in code that must not throw (decided by reviewer).
  evidence="uncaught_exception"; sink="availability"; cwe="CWE-248"; severity="LOW"; signature="py-exception"
fi

# Extract top app frames (strip addresses, line-numbers, sanitizer/interpreter glue).
# Anchor C++ frame source to end-of-line so signatures with spaces are not truncated.
FRAMES="$(printf '%s' "$TXT" \
  | grep -aE '#[0-9]+ ' \
  | sed -E 's/0x[0-9a-fA-F]+//g; s/\+0x[0-9a-fA-F]+//g; s/:[0-9]+:[0-9]+//g; s/:[0-9]+//g' \
  | grep -avE 'libclang_rt|sanitizer|__asan|__ubsan|_PyEval|ceval|atheris|libfuzzer|llvm|/usr/lib' \
  | grep -aoE 'in [^[:cntrl:]]+$' \
  | head -3 || true)"
# stack_hash is computed from PATH-INDEPENDENT frames (file paths reduced to basenames) so it is
# stable across machines/workdirs/build roots — only the symbol+basename identity matters. The raw
# FRAMES (with paths) are kept for display and for the code/ membership test below.
HASH_FRAMES="$(printf '%s' "$FRAMES" | sed -E 's#[^ ]*/([^/ ]+)$#\1#')"
STACK_HASH="$(printf '%s' "$HASH_FRAMES" | sha256sum | awk '{print $1}')"

# Gate policy differs by evidence class:
#  - memory/signal/abort/check oracles MUST have a native crash frame inside code/ (not harness-only).
#  - contract oracles (invariant/differential/metamorphic) raise a plain AssertionError in the test
#    file: they have NO native frame, so they are gated instead on (recorded input + cited kernel
#    file:line in the candidate + frozen-seed deterministic replay) — enforced by confirm_finding.sh.
case "$evidence" in
  asan|ubsan|msan|signal_segv|signal_fpe|abort|check_assert) REQ_NATIVE=true;;
  *) REQ_NATIVE=false;;
esac
HAS_CODE_FRAME=false
printf '%s' "$FRAMES" | grep -q 'code/' && HAS_CODE_FRAME=true

# Minimize crashing input if requested and possible.
MIN_INPUT=""
if [ "$MIN" = 1 ] && [ -n "$INPUT" ] && [ -f "$INPUT" ] && [ -n "$BIN" ] && [ -x "$BIN" ]; then
  MINOUT="${INPUT}.min"
  if "$BIN" -minimize_crash=1 -runs=20000 -exact_artifact_path="$MINOUT" "$INPUT" >/dev/null 2>&1; then
    MIN_INPUT="$MINOUT"
  elif command -v afl-tmin >/dev/null 2>&1; then
    afl-tmin -i "$INPUT" -o "$MINOUT" -- "$BIN" @@ >/dev/null 2>&1 && MIN_INPUT="$MINOUT" || true
  fi
fi

jq -n --arg ev "$evidence" --arg sink "$sink" --arg cwe "$cwe" --arg sev "$severity" \
  --arg sig "$signature" --arg sh "$STACK_HASH" --arg frames "$FRAMES" \
  --arg input "$INPUT" --arg min "$MIN_INPUT" --arg log "$LOG" \
  --argjson reqnative "$REQ_NATIVE" --argjson codeframe "$HAS_CODE_FRAME" \
  '{evidence_type:$ev, sink_class:$sink, cwe:$cwe, severity:$sev, signature:$sig,
    stack_hash:$sh, top_frames:($frames|split("\n")|map(select(length>0))),
    crash_input:$input, minimized_input:$min, log:$log,
    requires_native_frame:$reqnative, has_code_frame:$codeframe,
    confirmed:(($ev!="none") and ((($reqnative|not)) or $codeframe))}'

[ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "${FINDINGS_DIR:-$(dirname "$LOG")}" \
  --phase triage --actor triage_crash.sh --kind decision \
  --summary "triage: $signature stack=$STACK_HASH" --blob "$LOG" >/dev/null 2>&1 || true
