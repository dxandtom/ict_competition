#!/usr/bin/env bash
# selftest.sh — 在竞赛运行前端到端地验证该 skill 的核心机制是否正常工作。
# 测试内容：ledger 的 init/append/verify + 篡改检测、blackbox_guard，以及完整的证明
# 闭环（构建一个真实的 ASAN 崩溃 -> 分诊 -> 生成 finding 脚手架 -> confirm_finding PASS），外加一个
# 负向测试：一个伪造的 CONFIRMED finding 必须被降级。自包含；使用临时目录树。
#
# 用法： selftest.sh [workdir]   （默认：新建的 mktemp 目录；产物保留在那里以供检查）
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

echo "== selftest 工作目录: $WORK =="
need jq || { echo "selftest 需要 jq" >&2; exit 2; }
need python3 || { echo "selftest 需要 python3" >&2; exit 2; }

# 一个极小的目标：包含一个可从 'parser' 触达的确定性越界写入。
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

echo "-- 1. blackbox_guard 自测"
if bash "$HERE/blackbox_guard.sh" selftest >/dev/null 2>&1; then ok "blackbox_guard 25 项检查"; else no "blackbox_guard 自测"; fi

echo "-- 2. ledger init/append/verify + 篡改"
if bash "$HERE/ledger.sh" init "$FIND" "$CODE" >/dev/null 2>&1; then ok "ledger init"; else no "ledger init"; fi
bash "$HERE/ledger.sh" append "$FIND" --phase recon --actor selftest --kind note --summary "step one" >/dev/null 2>&1 \
  && ok "ledger append #1" || no "ledger append #1"
bash "$HERE/ledger.sh" append "$FIND" --phase sca --actor selftest --kind tool_call --summary "step two" >/dev/null 2>&1 \
  && ok "ledger append #2" || no "ledger append #2"
if bash "$HERE/ledger.sh" verify "$FIND" >/dev/null 2>&1; then ok "ledger verify 完好"; else no "ledger verify 完好"; fi
# 篡改：翻转 payload 中的一个字节，确认链断裂
cp "$FIND/ledger.jsonl" "$WORK/ledger.bak"
python3 - "$FIND/ledger.jsonl" <<'PY'
import json,sys
p=sys.argv[1]; ls=open(p).read().splitlines()
d=json.loads(ls[1]); d["summary"]="TAMPERED"; ls[1]=json.dumps(d)
open(p,"w").write("\n".join(ls)+"\n")
PY
if bash "$HERE/ledger.sh" verify "$FIND" >/dev/null 2>&1; then no "未检测到篡改"; else ok "检测到篡改"; fi
cp "$WORK/ledger.bak" "$FIND/ledger.jsonl"   # 恢复

echo "-- 3. 证明闭环：真实 ASAN 崩溃 -> 分诊 -> 确认"
# 使用任意一个能真正链接出 ASAN 二进制的编译器（gcc 自带 libasan；某些 clang 安装
# 缺少 asan 运行时）。逐个尝试直到有一个能链接成功。
POC="$WORK/poc"; CC=""
for c in gcc clang cc; do
  need "$c" || continue
  if "$c" -fsanitize=address,undefined -fno-omit-frame-pointer -g "$WORK/poc.c" "$CODE/vuln.c" -o "$POC" 2>"$WORK/build.$c.log"; then CC="$c"; break; fi
done
if [ -z "$CC" ]; then sk "没有可用 ASAN 运行时的编译器；跳过证明闭环"; else
  if true; then
    ok "已构建 ASAN PoC ($CC)"
    FDIR="$(bash "$HERE/new_finding.sh" "$FIND" --title "oob-write-in-parser" --sink oob_rw --severity HIGH 2>/dev/null)"
    [ -d "$FDIR" ] && ok "已生成脚手架 $(basename "$FDIR")" || no "生成 finding 脚手架"
    mkdir -p "$FDIR/evidence"; cp "$WORK/poc.c" "$FDIR/poc.c"
    export ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:detect_leaks=0"
    # 用 bash -c 包裹，使 PoC 的 SIGABRT 转化为正常的退出码（避免 "Aborted" 作业消息）
    for i in 1 2 3; do bash -c '"$1" >"$2" 2>&1' _ "$POC" "$FDIR/evidence/run$i.log" || true; done
    if grep -qiE 'AddressSanitizer|stack-buffer-overflow' "$FDIR/evidence/run1.log"; then ok "ASAN 已触发"; else no "ASAN 未触发（见 $FDIR/evidence/run1.log）"; fi
    FINDINGS_DIR="$FIND" bash "$HERE/triage_crash.sh" "$FDIR/evidence/run1.log" > "$FDIR/oracle.json" 2>/dev/null
    EV="$(jq -r '.evidence_type' "$FDIR/oracle.json" 2>/dev/null)"; CF="$(jq -r '.confirmed' "$FDIR/oracle.json" 2>/dev/null)"
    [ "$EV" = "asan" ] && ok "分诊 -> asan" || no "分诊 evidence_type=$EV（期望 asan）"
    [ "$CF" = "true" ] && ok "分诊 confirmed=true" || no "分诊 confirmed=$CF"
    # 根据 oracle 将 finding.json 填充为 CONFIRMED
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
    if bash "$HERE/confirm_finding.sh" validate "$FDIR" >/dev/null 2>&1; then ok "confirm_finding PASS（真实 PoC）"; else no "confirm_finding 拒绝了真实的 PoC"; fi

    echo "-- 4. 负向测试：伪造的 CONFIRMED 必须被降级"
    BAD="$(bash "$HERE/new_finding.sh" "$FIND" --title "forged" --sink oob_rw --severity CRITICAL 2>/dev/null)"
    python3 - "$BAD/finding.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d["status"]="CONFIRMED"  # no poc, no evidence, empty oracle
json.dump(d,open(sys.argv[1],"w"),indent=2)
PY
    if bash "$HERE/confirm_finding.sh" validate "$BAD" >/dev/null 2>&1; then no "伪造的 finding 未被降级"; else ok "伪造的 finding 已被降级"; fi
  else
    sk "ASAN 构建失败（编译器缺少 sanitizer？）— 见 $WORK/build.log"
  fi
fi

echo "== selftest: $pass pass, $fail fail, $skip skip =="
[ "$fail" = 0 ]
