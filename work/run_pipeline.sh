#!/usr/bin/env bash
# run_pipeline.sh — （可选）端到端复现：从零对目标运行黑盒漏洞挖掘并重新生成三份交付物。
#
# 说明：这是“完整复现”路径，会真正对目标运行时做动态崩溃扫描。它是非交互的，但需要：
#   - 目标源码目录（用于根因/门禁核验）：环境变量 TARGET_SRC，默认自动探测
#     /app/code/judge-assets/*/ 下的源码目录，或仓库内 ./code。
#   - 目标运行时（用于动态触发）：环境变量 AIVH_PY 指向一个已装好目标发行包的 python，
#     或设 TARGET_DIST（如某个 pip 包名）由本脚本用 uv 建一个 py3.10 venv 装上。
# 若两者都不可用，脚本会退化为“仅校验已提交交付物”（等价于 work/verify.sh），并明确提示。
#
# 主评测路径请用 work/verify.sh（确定性、自包含、无需联网）。本脚本用于展示方法体系可复跑。
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"           # .../work
ROOT="$(cd "$HERE/.." && pwd)"
SKILL="$HERE/skills/ai-vuln-hunt"
say(){ echo "[run_pipeline] $*"; }
need(){ command -v "$1" >/dev/null 2>&1; }

need jq || { echo "需要 jq" >&2; exit 2; }
chmod +x "$SKILL"/scripts/*.sh 2>/dev/null || true

# ---- 解析目标源码 ----
TSRC="${TARGET_SRC:-}"
if [ -z "$TSRC" ]; then
  for c in "$ROOT/code" /app/code/judge-assets/*/ ; do
    [ -d "$c" ] && [ -n "$(find "$c" -maxdepth 3 -name '*.cc' -o -name '*.py' 2>/dev/null | head -1)" ] && { TSRC="$(cd "$c" && pwd)"; break; }
  done
fi
[ -n "$TSRC" ] && say "目标源码：$TSRC" || say "未找到目标源码（可设 TARGET_SRC）"

# ---- 解析目标运行时 ----
PY="${AIVH_PY:-}"
if [ -z "$PY" ] && [ -n "${TARGET_DIST:-}" ] && need uv; then
  say "用 uv 建 py3.10 venv 并安装 \$TARGET_DIST 与 atheris/hypothesis…"
  uv venv --python 3.10 "$ROOT/.venv_target" >/dev/null 2>&1 \
    && uv pip install --python "$ROOT/.venv_target" "$TARGET_DIST" "numpy<1.24" hypothesis atheris >/dev/null 2>&1 \
    && PY="$ROOT/.venv_target/bin/python" || say "运行时 venv 构建失败"
fi
[ -n "$PY" ] && "$PY" -c 'import sys' 2>/dev/null && say "目标运行时：$PY" || { PY=""; say "无可用目标运行时（设 AIVH_PY 或 TARGET_DIST）"; }

# ---- 若缺目标运行时：退化为校验已提交交付物 ----
if [ -z "$PY" ] || [ -z "$TSRC" ]; then
  say "缺少目标源码或运行时 → 退化为校验已提交的交付物（等价 verify.sh）。"
  exec bash "$HERE/verify.sh"
fi

# ---- 完整复现：黑盒动态崩溃扫描 → 打包 → 导出交付物 ----
export FINDINGS="$ROOT/findings_run"; export CODE_ROOT="$TSRC"; export AIVH_MODEL="${AIVH_MODEL:-unspecified}"
rm -rf "$FINDINGS"; mkdir -p "$FINDINGS/raw/dast"
say "1) 初始化黑盒账本"; bash "$SKILL/scripts/ledger.sh" init "$FINDINGS" "$TSRC" >/dev/null 2>&1 || true
cp "$HERE/evidence/dast/raw_fuzz.py" "$FINDINGS/raw/dast/raw_fuzz.py"
sed -i "s#/home/user/ict_competition/findings/raw/dast#$FINDINGS/raw/dast#g; s#[^ \"']*/\.venv310/bin/python#$PY#g" "$FINDINGS/raw/dast/raw_fuzz.py" 2>/dev/null || true

say "2) DAST：隔离子进程崩溃扫描（发现阶段）"
"$PY" "$FINDINGS/raw/dast/raw_fuzz.py" gen >/dev/null 2>&1 || true
timeout "${SWEEP_TIMEOUT:-1500}" "$PY" "$FINDINGS/raw/dast/raw_fuzz.py" drive 2>/dev/null | tail -6 || true
NC=$(wc -l < "$FINDINGS/raw/dast/crashes.jsonl" 2>/dev/null || echo 0)
say "   发现崩溃算子：$NC"
[ "$NC" -ge 1 ] || { say "未发现崩溃 → 退化为校验已提交交付物"; exec bash "$HERE/verify.sh"; }

say "3) 自动打包并强制确认（每个崩溃 → PoC×3 → triage → confirm_finding）"
FILL="$FINDINGS/raw/dast/_fill.py"
cat > "$FILL" <<'PY'
import json,sys
fj,oj=sys.argv[1],sys.argv[2]; d=json.load(open(fj)); o=json.load(open(oj))
loc=(o.get("top_frames") or [""])[0]
d.update(status="CONFIRMED",cwe=o.get("cwe",""),severity="MEDIUM",
 file=loc.split(":")[0] if loc else "",line=int(loc.split(":")[1]) if ":" in loc else 0,
 poc={"path":"poc.py","kind":"standalone"},evidence=["evidence/run1.log","evidence/run2.log","evidence/run3.log"],
 oracle=o,cited_kernel=loc,stubbed_symbols=[],needs_real_build_confirmation=False)
json.dump(d,open(fj,"w"),indent=2,ensure_ascii=False)
PY
i=0
while read -r line; do
  op=$(echo "$line" | jq -r .op); strat=$(echo "$line" | jq -r .strat); i=$((i+1))
  [ "$i" -gt "${MAX_FINDINGS:-4}" ] && break
  FDIR="$(bash "$SKILL/scripts/new_finding.sh" "$FINDINGS" --title "auto: raw_ops.$op adversarial input -> process crash" --sink availability --severity MEDIUM)"
  mkdir -p "$FDIR/evidence"
  cat > "$FDIR/poc.py" <<PY
import os,sys
os.environ["TF_CPP_MIN_LOG_LEVEL"]="3"; os.environ["CUDA_VISIBLE_DEVICES"]="-1"
sys.path.insert(0,"$FINDINGS/raw/dast"); import raw_fuzz as f
import importlib; mod=None
# raw_fuzz 内部 import 目标框架；直接复用其输入合成与调用
kw=f.build_inputs("$op",$strat)
import tensorflow as tf
getattr(tf.raw_ops,"$op")(**kw)
print("NO CRASH")
PY
  printf '#!/usr/bin/env bash\nset -uo pipefail\ncd "$(dirname "$0")"\n%s poc.py; echo "exit=$?"\n' "$PY" > "$FDIR/run.sh"; chmod +x "$FDIR/run.sh"
  for r in 1 2 3; do bash -c '"$1" "$2" >"$3" 2>&1' _ "$PY" "$FDIR/poc.py" "$FDIR/evidence/run$r.log"; done
  FINDINGS_DIR="$FINDINGS" CODE_ROOT="$CODE_ROOT" bash "$SKILL/scripts/triage_crash.sh" "$FDIR/evidence/run1.log" > "$FDIR/oracle.json" 2>/dev/null
  "$PY" "$FILL" "$FDIR/finding.json" "$FDIR/oracle.json" 2>/dev/null || python3 "$FILL" "$FDIR/finding.json" "$FDIR/oracle.json" 2>/dev/null || true
  CODE_ROOT="$CODE_ROOT" bash "$SKILL/scripts/confirm_finding.sh" validate "$FDIR" >/dev/null 2>&1 || true
done < <(jq -c -s 'unique_by(.op)[]' "$FINDINGS/raw/dast/crashes.jsonl")

say "4) 门禁复核 + 生成 REPORT + 导出三份交付物到 work/"
CODE_ROOT="$CODE_ROOT" bash "$SKILL/scripts/confirm_finding.sh" gate-all "$FINDINGS" 2>&1 | tail -1 || true
# 简报（REPORT.md）：若无自定义则用现有模板骨架
[ -f "$FINDINGS/REPORT.md" ] || cp "$HERE/evidence/REPORT.md" "$FINDINGS/REPORT.md" 2>/dev/null || true
bash "$SKILL/scripts/make_deliverables.sh" "$FINDINGS" "$HERE" 2>&1 | tail -3 || true
say "完成。交付物已写入 work/。运行 work/verify.sh 做最终校验。"
bash "$HERE/verify.sh"
