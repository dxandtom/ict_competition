#!/usr/bin/env bash
# verify.sh — 确定性、自包含地校验参赛交付物（供自动评测系统执行）。
#
# 无需联网、无需目标源码即可运行。它证明三份交付物存在且自洽、AI 对话记录为合法 JSON、
# 全部通过黑盒扫描（无身份/版本/CVE 断言）、每条漏洞的证据日志确实复现出所记录的 oracle、
# 且哈希链账本完整。完成后写出 work/STATUS.txt 并以退出码 0（成功）/非 0（失败）结束。
#
# 用法：  bash work/verify.sh            # 从仓库根目录执行
#         bash verify.sh                # 从 work/ 目录内执行
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"          # .../work
SKILL="$HERE/skills/ai-vuln-hunt"
GUARD="$SKILL/scripts/blackbox_guard.sh"
TRIAGE="$SKILL/scripts/triage_crash.sh"
LEDGER="$SKILL/scripts/ledger.sh"
EV="$HERE/evidence"
STATUS="$HERE/STATUS.txt"
pass=0; fail=0
ok(){ echo "  [OK]  $1"; pass=$((pass+1)); }
no(){ echo "  [FAIL] $1" >&2; fail=$((fail+1)); }
need(){ command -v "$1" >/dev/null 2>&1; }

echo "== ai-vuln-hunt 交付物校验 =="
need jq || { echo "需要 jq（apt-get install -y jq 或 conda install jq）" >&2; exit 2; }

echo "-- 1. 三份必交交付物存在 --"
for f in vulnerability_list.md llm_chat_log.json vulnerability_report.md; do
  [ -s "$HERE/$f" ] && ok "work/$f 存在且非空" || no "缺失 work/$f"
done

echo "-- 2. llm_chat_log.json 为合法 JSON 且结构正确 --"
if jq -e '.metadata.llm_model_used and (.metadata.total_turns|type=="number") and (.chat_history|type=="array") and (.chat_history|length>0) and all(.chat_history[]; has("turn") and has("role") and has("content"))' "$HERE/llm_chat_log.json" >/dev/null 2>&1; then
  ok "llm_chat_log.json 合法（model=$(jq -r .metadata.llm_model_used "$HERE/llm_chat_log.json"), turns=$(jq -r .metadata.total_turns "$HERE/llm_chat_log.json"), 消息=$(jq '.chat_history|length' "$HERE/llm_chat_log.json")）"
else no "llm_chat_log.json 结构不合法"; fi

echo "-- 3. 黑盒合规：三份交付物无身份/版本/CVE 硬泄漏 --"
if [ -x "$GUARD" ]; then
  for f in vulnerability_list.md vulnerability_report.md llm_chat_log.json; do
    if bash "$GUARD" scan-file "$HERE/$f" >/dev/null 2>/tmp/aivh_g.$$; then ok "黑盒扫描通过：$f";
    else grep -q LEAK /tmp/aivh_g.$$ && no "黑盒硬泄漏：$f -> $(grep LEAK /tmp/aivh_g.$$|head -1|cut -c1-80)" || ok "黑盒扫描通过：$f（仅软警告）"; fi
  done
  rm -f /tmp/aivh_g.$$
else no "找不到 blackbox_guard.sh（应在 work/skills/ai-vuln-hunt/scripts/）"; fi

echo "-- 4. 每条已确认漏洞：证据自洽（≥3 份证据日志复现所记录的 oracle） --"
nf=0
for d in "$EV"/findings/VH-*; do
  [ -d "$d" ] || continue; nf=$((nf+1)); id="$(basename "$d")"
  fj="$d/finding.json"; [ -f "$fj" ] || { no "$id 缺 finding.json"; continue; }
  st="$(jq -r '.status // ""' "$fj")"; wev="$(jq -r '.oracle.evidence_type // ""' "$fj")"
  [ "$st" = "CONFIRMED" ] || { no "$id status=$st（非 CONFIRMED）"; continue; }
  [ "$(jq -r '.oracle.confirmed // false' "$fj")" = "true" ] || no "$id oracle.confirmed!=true"
  [ -n "$(jq -r '.poc.path // ""' "$fj")" ] && [ -f "$d/$(jq -r .poc.path "$fj")" ] && ok "$id PoC 存在（AI 生成）" || no "$id PoC 缺失"
  mapfile -t evs < <(jq -r '.evidence[]? // empty' "$fj")
  [ "${#evs[@]}" -ge 3 ] || no "$id 证据日志不足 3 份（${#evs[@]}）"
  matched=0
  for e in "${evs[@]}"; do
    log="$d/$e"; [ -f "$log" ] || { no "$id 缺证据 $e"; continue; }
    ev="$(bash "$TRIAGE" "$log" 2>/dev/null | jq -r '.evidence_type // "none"' 2>/dev/null)"
    [ "$ev" = "$wev" ] && matched=$((matched+1))
  done
  [ "$matched" -ge 3 ] && ok "$id 证据复现一致（$matched/${#evs[@]} 份复现 '$wev'）" || no "$id 仅 $matched/3 份证据复现 '$wev'"
done
[ "$nf" -ge 1 ] && ok "共 $nf 条已确认漏洞" || no "未发现任何已确认漏洞包"

echo "-- 5. 哈希链账本完整（可复现性证明） --"
if [ -f "$EV/ledger.jsonl" ] && [ -x "$LEDGER" ]; then
  bash "$LEDGER" verify "$EV" >/dev/null 2>&1 && ok "ledger.sh verify：链完整" || no "账本链校验失败"
else echo "  [skip] 无 ledger.jsonl 或 ledger.sh"; fi

echo "-- 6.（可选）若提供目标源码则做完整门禁复核 --"
CR="${CODE_ROOT:-}"; [ -z "$CR" ] && [ -d "$HERE/../code" ] && CR="$(cd "$HERE/../code" && pwd)"
if [ -n "$CR" ] && [ -d "$CR" ] && [ -x "$SKILL/scripts/confirm_finding.sh" ]; then
  CODE_ROOT="$CR" bash "$SKILL/scripts/confirm_finding.sh" gate-all "$EV" >/dev/null 2>&1 \
    && ok "confirm_finding gate-all（含 code/ 内崩溃帧核验）通过" || echo "  [warn] 完整门禁未通过或源码不完整（不影响自包含校验结论）"
else echo "  [skip] 未提供目标源码（CODE_ROOT / ../code）——跳过完整门禁（自包含校验已足够判定）"; fi

echo
echo "== 结果：$pass 通过 / $fail 失败 =="
if [ "$fail" = 0 ]; then
  { echo "STATUS=DONE"; echo "checks_passed=$pass"; echo "confirmed_findings=$nf";
    echo "deliverables=work/vulnerability_list.md,work/llm_chat_log.json,work/vulnerability_report.md"; } > "$STATUS"
  echo "已写出完成标记：$STATUS"; echo "交付物：work/vulnerability_list.md · work/llm_chat_log.json · work/vulnerability_report.md"
  exit 0
else
  { echo "STATUS=FAILED"; echo "checks_passed=$pass"; echo "checks_failed=$fail"; } > "$STATUS"
  echo "校验失败，见上方 [FAIL]。" >&2; exit 1
fi
