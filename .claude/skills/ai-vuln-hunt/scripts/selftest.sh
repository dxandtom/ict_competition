#!/usr/bin/env bash
# selftest.sh — prove the skill's machinery works end-to-end BEFORE a competition run.
# Exercises: ledger init/append/verify + tamper detection, blackbox_guard, and the full proof
# loop (build a real ASAN crash -> triage -> scaffold finding -> confirm_finding PASS), plus a
# negative test that a forged CONFIRMED finding is DEMOTED. Self-contained; uses a temp tree.
#
# Usage: selftest.sh [workdir]   (default: a fresh mktemp dir; artifacts left there for inspection)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-$(mktemp -d)}"
CODE="$WORK/code"; FIND="$WORK/findings"
mkdir -p "$CODE"
pass=0; fail=0; skip=0
ok(){ echo "  ok: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1" >&2; fail=$((fail+1)); }
sk(){ echo "  skip: $1"; skip=$((skip+1)); }
need(){ command -v "$1" >/dev/null 2>&1; }

echo "== selftest workdir: $WORK =="
need jq || { echo "jq required for selftest" >&2; exit 2; }
need python3 || { echo "python3 required for selftest" >&2; exit 2; }

# A tiny target with a deterministic out-of-bounds write reachable from a 'parser'.
cat > "$CODE/vuln.c" <<'EOF'
#include <stddef.h>
/* writes v at buf[idx] with no bounds check — classic OOB sink */
void write_at(unsigned char *buf, int idx, unsigned char v) { buf[idx] = v; }
int parse_and_store(int idx) {
  unsigned char buf[16];
  write_at(buf, idx, 0x41);   /* idx>=16 => stack-buffer-overflow */
  return buf[0];
}
EOF
cat > "$WORK/poc.c" <<'EOF'
extern int parse_and_store(int);
int main(void) { return parse_and_store(20); }   /* idx 20 lands in ASAN's redzone => clean report */
EOF

echo "-- 1. blackbox_guard selftest"
if bash "$HERE/blackbox_guard.sh" selftest >/dev/null 2>&1; then ok "blackbox_guard 25 checks"; else no "blackbox_guard selftest"; fi

echo "-- 2. ledger init/append/verify + tamper"
if bash "$HERE/ledger.sh" init "$FIND" "$CODE" >/dev/null 2>&1; then ok "ledger init"; else no "ledger init"; fi
bash "$HERE/ledger.sh" append "$FIND" --phase recon --actor selftest --kind note --summary "step one" >/dev/null 2>&1 \
  && ok "ledger append #1" || no "ledger append #1"
bash "$HERE/ledger.sh" append "$FIND" --phase sca --actor selftest --kind tool_call --summary "step two" >/dev/null 2>&1 \
  && ok "ledger append #2" || no "ledger append #2"
if bash "$HERE/ledger.sh" verify "$FIND" >/dev/null 2>&1; then ok "ledger verify intact"; else no "ledger verify intact"; fi
# tamper: flip a byte in a payload and confirm the chain breaks
cp "$FIND/ledger.jsonl" "$WORK/ledger.bak"
python3 - "$FIND/ledger.jsonl" <<'PY'
import json,sys
p=sys.argv[1]; ls=open(p).read().splitlines()
d=json.loads(ls[1]); d["summary"]="TAMPERED"; ls[1]=json.dumps(d)
open(p,"w").write("\n".join(ls)+"\n")
PY
if bash "$HERE/ledger.sh" verify "$FIND" >/dev/null 2>&1; then no "tamper NOT detected"; else ok "tamper detected"; fi
cp "$WORK/ledger.bak" "$FIND/ledger.jsonl"   # restore

echo "-- 3. proof loop: real ASAN crash -> triage -> confirm"
# Use whichever compiler can actually LINK an ASAN binary (gcc ships libasan; some clang installs
# lack the asan runtime). Try each until one links.
POC="$WORK/poc"; CC=""
for c in gcc clang cc; do
  need "$c" || continue
  if "$c" -fsanitize=address,undefined -fno-omit-frame-pointer -g "$WORK/poc.c" "$CODE/vuln.c" -o "$POC" 2>"$WORK/build.$c.log"; then CC="$c"; break; fi
done
if [ -z "$CC" ]; then sk "no compiler with a working ASAN runtime; proof-loop skipped"; else
  if true; then
    ok "built ASAN PoC ($CC)"
    FDIR="$(bash "$HERE/new_finding.sh" "$FIND" --title "oob-write-in-parser" --sink oob_rw --severity HIGH 2>/dev/null)"
    [ -d "$FDIR" ] && ok "scaffolded $(basename "$FDIR")" || no "scaffold finding"
    mkdir -p "$FDIR/evidence"; cp "$WORK/poc.c" "$FDIR/poc.c"
    export ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:detect_leaks=0"
    # wrap in bash -c so the PoC's SIGABRT becomes a normal exit code (no "Aborted" job message)
    for i in 1 2 3; do bash -c '"$1" >"$2" 2>&1' _ "$POC" "$FDIR/evidence/run$i.log" || true; done
    if grep -qiE 'AddressSanitizer|stack-buffer-overflow' "$FDIR/evidence/run1.log"; then ok "ASAN fired"; else no "ASAN did not fire (see $FDIR/evidence/run1.log)"; fi
    FINDINGS_DIR="$FIND" bash "$HERE/triage_crash.sh" "$FDIR/evidence/run1.log" > "$FDIR/oracle.json" 2>/dev/null
    EV="$(jq -r '.evidence_type' "$FDIR/oracle.json" 2>/dev/null)"; CF="$(jq -r '.confirmed' "$FDIR/oracle.json" 2>/dev/null)"
    [ "$EV" = "asan" ] && ok "triage -> asan" || no "triage evidence_type=$EV (want asan)"
    [ "$CF" = "true" ] && ok "triage confirmed=true" || no "triage confirmed=$CF"
    # fill finding.json to CONFIRMED from the oracle
    python3 - "$FDIR/finding.json" "$FDIR/oracle.json" <<'PY'
import json,sys
fj,oj=sys.argv[1],sys.argv[2]
d=json.load(open(fj)); o=json.load(open(oj))
d.update(status="CONFIRMED", cwe=o.get("cwe",""), severity="HIGH",
         file="code/vuln.c", line=3, entry_point="parse_and_store",
         poc={"path":"poc.c","kind":"standalone"},
         evidence=["evidence/run1.log","evidence/run2.log","evidence/run3.log"],
         oracle=o, stubbed_symbols=[], needs_real_build_confirmation=False)
json.dump(d,open(fj,"w"),indent=2)
PY
    if bash "$HERE/confirm_finding.sh" validate "$FDIR" >/dev/null 2>&1; then ok "confirm_finding PASS (genuine PoC)"; else no "confirm_finding rejected a genuine PoC"; fi

    echo "-- 4. negative test: forged CONFIRMED must be DEMOTED"
    BAD="$(bash "$HERE/new_finding.sh" "$FIND" --title "forged" --sink oob_rw --severity CRITICAL 2>/dev/null)"
    python3 - "$BAD/finding.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d["status"]="CONFIRMED"  # no poc, no evidence, empty oracle
json.dump(d,open(sys.argv[1],"w"),indent=2)
PY
    if bash "$HERE/confirm_finding.sh" validate "$BAD" >/dev/null 2>&1; then no "forged finding NOT demoted"; else ok "forged finding demoted"; fi
  else
    sk "ASAN build failed (compiler lacks sanitizers?) — see $WORK/build.log"
  fi
fi

echo "== selftest: $pass pass, $fail fail, $skip skip =="
[ "$fail" = 0 ]
