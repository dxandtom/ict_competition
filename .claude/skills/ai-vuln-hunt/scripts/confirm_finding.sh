#!/usr/bin/env bash
# confirm_finding.sh — the ENFORCED proof gate. No finding becomes/stays CONFIRMED unless it
# passes this. "No PoC, no bug" is enforced here, not merely documented.
#
# For a finding whose finding.json says status=CONFIRMED it checks:
#   1. finding.json validates against templates/finding.schema.json (jsonschema if available,
#      else a built-in structural check).
#   2. poc.path exists; >=3 evidence logs exist (the "deterministic 3x" requirement).
#   3. Re-runs triage_crash.sh on EVERY evidence log and requires all of them to reproduce the
#      SAME oracle (evidence_type), and — for native oracles — the SAME stack_hash. This is the
#      real reproduction proof, independent of the recorded oracle.json.
#   4. oracle.confirmed == true.
#   5. Class-specific:
#        memory/signal/abort/check  -> oracle.has_code_frame == true (crash is inside code/,
#                                      not a harness-only artifact).
#        contract (invariant/diff/  -> cited_kernel != "" AND failing_input file exists
#          metamorphic)                (these oracles have no native frame; gated on this instead).
#        stubbed single-unit build  -> if stubbed_symbols non-empty then
#                                      needs_real_build_confirmation == false (re-confirmed on real build).
#
# Anything failing => the finding is DEMOTED to UNCONFIRMED (status rewritten + moved to
# unconfirmed/) and the script exits non-zero. `gate-all` exits non-zero if ANY CONFIRMED
# finding fails — wire it into REPORT generation so a bad finding can never be published.
#
# Usage:
#   confirm_finding.sh validate <finding_dir>            # check & demote on failure
#   confirm_finding.sh gate-all <findings_dir> [--strict-demote]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
SCHEMA="$SKILL/templates/finding.schema.json"
command -v jq >/dev/null 2>&1 || { echo "confirm_finding.sh: jq required" >&2; exit 2; }

schema_validate() { # $1=finding.json  -> 0 ok, 1 invalid, 2 no validator (treated as soft-ok)
  local fj="$1"
  if command -v check-jsonschema >/dev/null 2>&1; then
    check-jsonschema --schemafile "$SCHEMA" "$fj" >/dev/null 2>&1 && return 0 || return 1
  fi
  if python3 -c 'import jsonschema' >/dev/null 2>&1; then
    python3 - "$SCHEMA" "$fj" <<'PY' >/dev/null 2>&1 && return 0 || return 1
import json,sys,jsonschema
s=json.load(open(sys.argv[1])); d=json.load(open(sys.argv[2]))
jsonschema.validate(d,s)
PY
  fi
  # Built-in structural fallback (no jsonschema installed): enforce the CONFIRMED conditional.
  python3 - "$fj" <<'PY' >/dev/null 2>&1 && return 0 || return 1
import json,sys
d=json.load(open(sys.argv[1]))
assert d.get("schema")=="finding-1.0"
assert d.get("status") in ("CONFIRMED","UNCONFIRMED")
if d.get("status")=="CONFIRMED":
    assert isinstance(d.get("poc"),dict) and d["poc"].get("path")
    ev=d.get("evidence"); assert isinstance(ev,list) and len(ev)>=1
    o=d.get("oracle"); assert isinstance(o,dict) and o.get("confirmed") is True
PY
}

validate_one() { # $1=finding_dir
  local DIR="$1" FJ; FJ="$DIR/finding.json"
  [ -f "$FJ" ] || { echo "[confirm] no finding.json in $DIR" >&2; return 2; }
  local status; status="$(jq -r '.status // "UNCONFIRMED"' "$FJ")"
  local FIND_ROOT; FIND_ROOT="$(cd "$DIR/../.." && pwd)"  # findings/
  led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND_ROOT" --phase confirm \
         --actor confirm_finding.sh "$@" >/dev/null 2>&1 || true; }

  if [ "$status" != "CONFIRMED" ]; then
    schema_validate "$FJ" || { echo "[confirm] $DIR: UNCONFIRMED but schema-invalid" >&2; return 1; }
    echo "[confirm] $(basename "$DIR"): UNCONFIRMED (ok, not published)"; return 0
  fi

  local reasons=()
  schema_validate "$FJ" || reasons+=("schema-invalid")

  local poc; poc="$(jq -r '.poc.path // ""' "$FJ")"
  [ -n "$poc" ] && [ -e "$DIR/$poc" -o -e "$poc" ] || reasons+=("poc-missing:$poc")

  # evidence logs (>=3 for deterministic reproduction)
  mapfile -t evs < <(jq -r '.evidence[]? // empty' "$FJ")
  if [ "${#evs[@]}" -lt 3 ]; then reasons+=("need>=3-evidence-logs(have ${#evs[@]})"); fi

  local want_ev want_sh reqnative codeframe
  want_ev="$(jq -r '.oracle.evidence_type // ""' "$FJ")"
  want_sh="$(jq -r '.oracle.stack_hash // ""' "$FJ")"
  reqnative="$(jq -r '.oracle.requires_native_frame // false' "$FJ")"
  codeframe="$(jq -r '.oracle.has_code_frame // false' "$FJ")"
  [ "$(jq -r '.oracle.confirmed // false' "$FJ")" = "true" ] || reasons+=("oracle.confirmed!=true")

  # Re-triage every evidence log => independent reproduction proof.
  local matched=0 i=0
  for e in "${evs[@]}"; do
    local p="$DIR/$e"; [ -f "$p" ] || p="$e"
    [ -f "$p" ] || { reasons+=("evidence-missing:$e"); continue; }
    local t; t="$(FINDINGS_DIR="$FIND_ROOT" bash "$HERE/triage_crash.sh" "$p" 2>/dev/null || echo '{}')"
    local ev sh; ev="$(printf '%s' "$t" | jq -r '.evidence_type // "none"')"
    sh="$(printf '%s' "$t" | jq -r '.stack_hash // ""')"
    i=$((i+1))
    if [ "$ev" = "$want_ev" ] && { [ "$reqnative" != "true" ] || [ "$sh" = "$want_sh" ]; }; then
      matched=$((matched+1))
    else
      reasons+=("evidence#$i reproduced '$ev'(sh=$sh) != expected '$want_ev'(sh=$want_sh)")
    fi
  done
  [ "$matched" -ge 3 ] || reasons+=("only $matched/3 evidence logs reproduce the oracle")

  # Class-specific gates
  case "$want_ev" in
    invariant_violation|differential_mismatch|metamorphic_violation)
      local ck fi_; ck="$(jq -r '.cited_kernel // ""' "$FJ")"; fi_="$(jq -r '.failing_input // ""' "$FJ")"
      [ -n "$ck" ] || reasons+=("contract-oracle-needs cited_kernel")
      { [ -n "$fi_" ] && { [ -e "$DIR/$fi_" ] || [ -e "$fi_" ]; }; } || reasons+=("contract-oracle-needs recorded failing_input file")
      ;;
    asan|ubsan|msan|signal_segv|signal_fpe|abort|check_assert)
      [ "$codeframe" = "true" ] || reasons+=("native-oracle without crash frame inside code/ (harness-only artifact?)")
      ;;
  esac

  # Stubbed single-unit build must be re-confirmed against the real build.
  local nstubs needreal
  nstubs="$(jq -r '(.stubbed_symbols // []) | length' "$FJ")"
  needreal="$(jq -r '.needs_real_build_confirmation // false' "$FJ")"
  if [ "$nstubs" -gt 0 ] && [ "$needreal" = "true" ]; then
    reasons+=("built with $nstubs weak stubs and not re-confirmed on the real build")
  fi

  if [ "${#reasons[@]}" -eq 0 ]; then
    echo "[confirm] $(basename "$DIR"): CONFIRMED ✓ ($matched/${#evs[@]} logs reproduce '$want_ev')"
    led --kind decision --summary "confirmed $(basename "$DIR") oracle=$want_ev"
    return 0
  fi

  echo "[confirm] $(basename "$DIR"): DEMOTED to UNCONFIRMED:" >&2
  printf '   - %s\n' "${reasons[@]}" >&2
  tmp="$(mktemp)"; jq '.status="UNCONFIRMED" | .notes=((.notes // "")+" [demoted by confirm_finding.sh: '"$(printf '%s; ' "${reasons[@]}" | sed "s/[\"']//g")"']")' "$FJ" > "$tmp" && mv "$tmp" "$FJ"
  mkdir -p "$FIND_ROOT/unconfirmed"
  mv "$DIR" "$FIND_ROOT/unconfirmed/" 2>/dev/null || true
  led --kind decision --summary "demoted $(basename "$DIR") (${#reasons[@]} reasons)"
  return 1
}

case "${1:-}" in
  validate) shift; validate_one "${1:?usage: confirm_finding.sh validate <finding_dir>}";;
  gate-all)
    shift; ROOT="${1:?usage: confirm_finding.sh gate-all <findings_dir>}"
    rc=0
    for d in "$ROOT/findings"/VH-*; do [ -d "$d" ] || continue; validate_one "$d" || rc=1; done
    if [ "$rc" = 0 ]; then echo "[confirm] gate-all: all CONFIRMED findings pass the proof gate";
    else echo "[confirm] gate-all: some findings failed and were demoted" >&2; fi
    exit $rc;;
  *) echo "usage: confirm_finding.sh {validate <finding_dir>|gate-all <findings_dir>}" >&2; exit 2;;
esac
