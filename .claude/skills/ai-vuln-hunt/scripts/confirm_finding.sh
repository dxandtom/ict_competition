#!/usr/bin/env bash
# confirm_finding.sh —强制的证据门禁。任何 finding 只有通过此检查才能成为/保持 CONFIRMED 状态。
# “没有 PoC，就没有 bug”这条规则在此强制执行，而非仅停留在文档层面。
#
# 对于 finding.json 中 status=CONFIRMED 的 finding，它会检查：
#   1. finding.json 通过 templates/finding.schema.json 校验（若可用则使用 jsonschema，
#      否则使用内置的结构性检查）。
#   2. poc.path 存在；存在 >=3 条证据日志（即“确定性 3 次”要求）。
#   3. 对每一条证据日志重新运行 triage_crash.sh，并要求它们全部复现出
#      相同的 oracle（evidence_type），并且——对于原生 oracle——具有相同的 stack_hash。
#      这是真正的复现证明，独立于已记录的 oracle.json。
#   4. oracle.confirmed == true。
#   5. 分类专属检查：
#        memory/signal/abort/check  -> oracle.has_code_frame == true（崩溃发生在 code/ 内部，
#                                      而非仅是 harness 自身的产物）。
#        contract (invariant/diff/  -> cited_kernel != "" 且 failing_input 文件存在
#          metamorphic)                （这些 oracle 没有原生帧，改为以此为门禁条件）。
#        stubbed single-unit build  -> 若 stubbed_symbols 非空，则要求
#                                      needs_real_build_confirmation == false（已在真实构建上重新确认）。
#
# 任何一项失败 => 该 finding 被降级为 UNCONFIRMED（重写 status 并移动到
# unconfirmed/），脚本以非零状态退出。只要有任一 CONFIRMED finding 失败，`gate-all`
# 就以非零退出——将其接入 REPORT 生成流程，使得有问题的 finding 永远无法被发布。
#
# 用法：
#   confirm_finding.sh validate <finding_dir>            # 检查，失败则降级
#   confirm_finding.sh gate-all <findings_dir> [--strict-demote]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
SCHEMA="$SKILL/templates/finding.schema.json"
command -v jq >/dev/null 2>&1 || { echo "confirm_finding.sh: 需要 jq" >&2; exit 2; }

schema_validate() { # $1=finding.json  -> 0 通过, 1 无效, 2 无校验器（视为软性通过）
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
  # 内置结构性回退（未安装 jsonschema 时）：强制执行 CONFIRMED 的条件约束。
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
  [ -f "$FJ" ] || { echo "[confirm] $DIR 中没有 finding.json" >&2; return 2; }
  local status; status="$(jq -r '.status // "UNCONFIRMED"' "$FJ")"
  local FIND_ROOT; FIND_ROOT="$(cd "$DIR/../.." && pwd)"  # findings/
  led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND_ROOT" --phase confirm \
         --actor confirm_finding.sh "$@" >/dev/null 2>&1 || true; }

  if [ "$status" != "CONFIRMED" ]; then
    schema_validate "$FJ" || { echo "[confirm] $DIR: UNCONFIRMED 但 schema 无效" >&2; return 1; }
    echo "[confirm] $(basename "$DIR"): UNCONFIRMED（正常，未发布）"; return 0
  fi

  local reasons=()
  schema_validate "$FJ" || reasons+=("schema-invalid")

  local poc; poc="$(jq -r '.poc.path // ""' "$FJ")"
  [ -n "$poc" ] && [ -e "$DIR/$poc" -o -e "$poc" ] || reasons+=("poc-missing:$poc")

  # 证据日志（确定性复现需要 >=3 条）
  mapfile -t evs < <(jq -r '.evidence[]? // empty' "$FJ")
  if [ "${#evs[@]}" -lt 3 ]; then reasons+=("need>=3-evidence-logs(have ${#evs[@]})"); fi

  local want_ev want_sh reqnative codeframe
  want_ev="$(jq -r '.oracle.evidence_type // ""' "$FJ")"
  want_sh="$(jq -r '.oracle.stack_hash // ""' "$FJ")"
  reqnative="$(jq -r '.oracle.requires_native_frame // false' "$FJ")"
  codeframe="$(jq -r '.oracle.has_code_frame // false' "$FJ")"
  [ "$(jq -r '.oracle.confirmed // false' "$FJ")" = "true" ] || reasons+=("oracle.confirmed!=true")

  # 重新 triage 每一条证据日志 => 独立的复现证明。
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

  # 分类专属门禁
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

  # 使用桩的单元构建必须在真实构建上重新确认。
  local nstubs needreal
  nstubs="$(jq -r '(.stubbed_symbols // []) | length' "$FJ")"
  needreal="$(jq -r '.needs_real_build_confirmation // false' "$FJ")"
  if [ "$nstubs" -gt 0 ] && [ "$needreal" = "true" ]; then
    reasons+=("built with $nstubs weak stubs and not re-confirmed on the real build")
  fi

  if [ "${#reasons[@]}" -eq 0 ]; then
    echo "[confirm] $(basename "$DIR"): CONFIRMED ✓（$matched/${#evs[@]} 条日志复现了 '$want_ev'）"
    led --kind decision --summary "confirmed $(basename "$DIR") oracle=$want_ev"
    return 0
  fi

  echo "[confirm] $(basename "$DIR"): 已降级为 UNCONFIRMED：" >&2
  printf '   - %s\n' "${reasons[@]}" >&2
  tmp="$(mktemp)"; jq '.status="UNCONFIRMED" | .notes=((.notes // "")+" [demoted by confirm_finding.sh: '"$(printf '%s; ' "${reasons[@]}" | sed "s/[\"']//g")"']")' "$FJ" > "$tmp" && mv "$tmp" "$FJ"
  mkdir -p "$FIND_ROOT/unconfirmed"
  mv "$DIR" "$FIND_ROOT/unconfirmed/" 2>/dev/null || true
  led --kind decision --summary "demoted $(basename "$DIR") (${#reasons[@]} reasons)"
  return 1
}

case "${1:-}" in
  validate) shift; validate_one "${1:?用法: confirm_finding.sh validate <finding_dir>}";;
  gate-all)
    shift; ROOT="${1:?用法: confirm_finding.sh gate-all <findings_dir>}"
    rc=0
    for d in "$ROOT/findings"/VH-*; do [ -d "$d" ] || continue; validate_one "$d" || rc=1; done
    if [ "$rc" = 0 ]; then echo "[confirm] gate-all: 所有 CONFIRMED finding 均通过证据门禁";
    else echo "[confirm] gate-all: 部分 finding 未通过并已被降级" >&2; fi
    exit $rc;;
  *) echo "用法: confirm_finding.sh {validate <finding_dir>|gate-all <findings_dir>}" >&2; exit 2;;
esac
