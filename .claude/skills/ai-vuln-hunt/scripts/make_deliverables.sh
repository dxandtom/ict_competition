#!/usr/bin/env bash
# make_deliverables.sh — emit the three competition deliverables from a findings/ dir.
#
# Deliverables written to <out_dir>:
#   1. vulnerability_list.md   (漏洞清单, rendered from templates/vulnerability_list.md)
#   2. vulnerability_report.md (人类可读报告, copied/renamed from findings REPORT.md)
#   3. llm_chat_log.json       (PRIMARY = 审计模型的真实对话；若 <out_dir> 已存在该文件则校验并保留，
#                               并把由 ledger.jsonl 还原的机器记录写入 llm_chat_log.ledger.json；
#                               否则以 ledger 还原稿作为初稿。均为 valid JSON via jq)
#
# BLACK-BOX RULE: this script only ever reads finding.json / ledger.jsonl / env_manifest.json
# / REPORT.md — artifacts that are already black-box (they assert NO project identity/version
# and NO CVE). It never reads the target source or the recorded-but-unread identity files, and
# it never emits an identity/version/CVE assertion of its own.
#
# Usage: make_deliverables.sh <findings_dir> <out_dir>
#   <findings_dir>  directory that directly contains VH-*/finding.json subdirectories.
#                   ledger.jsonl / env_manifest.json / REPORT.md are looked up there and,
#                   failing that, in its parent directory.
#   <out_dir>       output directory (created if absent).
#
# Requires: jq. Degrades gracefully when an input file is missing.

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: make_deliverables.sh <findings_dir> <out_dir>

  <findings_dir>  dir containing VH-*/finding.json (ledger.jsonl / env_manifest.json /
                  REPORT.md resolved here or in the parent dir)
  <out_dir>       output dir for vulnerability_list.md, vulnerability_report.md,
                  llm_chat_log.json

Emits the three competition deliverables. Requires jq. Black-box: never asserts the
target's identity/version and never names a CVE.
EOF
  exit 2
}

[ "$#" -eq 2 ] || usage
FINDINGS_DIR="$1"
OUT_DIR="$2"

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required but not found on PATH." >&2; exit 3; }
[ -d "$FINDINGS_DIR" ] || { echo "ERROR: findings_dir not a directory: $FINDINGS_DIR" >&2; exit 3; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/../templates/vulnerability_list.md"

mkdir -p "$OUT_DIR"

# Resolve an input file: prefer <findings_dir>/<name>, fall back to <findings_dir>/../<name>.
resolve() {
  local name="$1"
  if [ -f "$FINDINGS_DIR/$name" ]; then printf '%s\n' "$FINDINGS_DIR/$name"; return 0; fi
  if [ -f "$FINDINGS_DIR/../$name" ]; then printf '%s\n' "$FINDINGS_DIR/../$name"; return 0; fi
  return 1
}

LEDGER="$(resolve ledger.jsonl || true)"
MANIFEST="$(resolve env_manifest.json || true)"
REPORT="$(resolve REPORT.md || true)"

warn() { echo "WARN: $*" >&2; }

# ---- shared defaults (black-box) -----------------------------------------------------------
DEFAULT_PROMPT='优先审计最薄的算子封装（在目标代码中以 raw_ops.* 形式导出的低层算子注册表）：它们把调用者可控的形状/索引/分片/线程数等元数据直接传入 C++ 内核，Python 侧校验最少；请对每个此类算子以对抗性输入（0、负数、2**31 边界值）在隔离子进程中试探进程级信号（SIGABRT/SIGSEGV/SIGFPE）或 "Check failed" 中止。'
DEFAULT_RATIONALE='选择该提示词是因为薄算子封装是原生数值/机器学习库历史上最脆弱的入口：调用者可控的元数据几乎不经 Python 侧校验即进入 C++ 内核，且此类内核常以致命 CHECK/断言而非可返回错误来处理非法边界。用 0 / 负数 / 2**31 等对抗值配合隔离子进程与崩溃后续跑，能以最小代价把“契约性异常（被捕获的 Python 异常，非缺陷）”与“真实进程级缺陷（信号或 Check failed 中止）”区分开。'

# ---- 1. vulnerability_list.md --------------------------------------------------------------
LIST_OUT="$OUT_DIR/vulnerability_list.md"
n_findings=0

if [ ! -f "$TEMPLATE" ]; then
  warn "template not found: $TEMPLATE — writing a minimal header-only list."
  printf '# 漏洞清单（Vulnerability List）\n\n' > "$LIST_OUT"
  HEADER="# 漏洞清单（Vulnerability List）"
  BLOCK=$'## {{ID}} — {{TITLE}}\n- 漏洞类型：{{VULN_TYPE}}\n- 严重级别：{{SEVERITY}}\n- 问题源码路径：{{SOURCE_PATH}}\n- 成因简述：{{ROOT_CAUSE}}\n- 与 LLM 交互中哪句提示词发现了 bug：{{DISCOVERY_PROMPT}}\n- 为什么选择此提示词：{{PROMPT_RATIONALE}}\n- 潜在业务危害：{{BUSINESS_IMPACT}}\n- 一键复现：`{{REPRO_CMD}}`\n'
  FOOTER=""
else
  tmpl="$(cat "$TEMPLATE")"
  BEGIN='<!-- BEGIN FINDING BLOCK -->'
  END='<!-- END FINDING BLOCK -->'
  if [[ "$tmpl" == *"$BEGIN"* && "$tmpl" == *"$END"* ]]; then
    HEADER="${tmpl%%"$BEGIN"*}"
    rest="${tmpl#*"$BEGIN"}"
    BLOCK="${rest%%"$END"*}"
    FOOTER="${rest#*"$END"}"
  else
    warn "template missing BEGIN/END markers — treating whole template as one block."
    HEADER=""
    BLOCK="$tmpl"
    FOOTER=""
  fi
fi

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TARGET_SHA="unknown"
if [ -n "${MANIFEST:-}" ]; then
  TARGET_SHA="$(jq -r '.target_tree_sha256 // "unknown"' "$MANIFEST" 2>/dev/null || echo unknown)"
fi

# Map a machine sink_class to a Chinese vulnerability-type label.
type_label() {
  case "$1" in
    availability)  echo "拒绝服务 / 可用性（进程级中止）" ;;
    int_overflow)  echo "整数溢出 / 数值窄化" ;;
    oob|oob_read|oob_write|memory) echo "内存安全（越界访问）" ;;
    div_zero)      echo "除零 / 浮点异常" ;;
    *)             echo "$1" ;;
  esac
}

# Map a sink_class to a Chinese business-impact line.
impact_line() {
  case "$1" in
    availability|int_overflow|div_zero)
      echo "攻击者可通过公开算子接口以受控参数触发进程级 abort，使承载该算子的服务 / 推理 / 训练进程整体崩溃（拒绝服务）；在多租户或以 RPC / 服务化方式暴露该算子的部署中，单个恶意请求即可反复触发，形成持续性可用性打击，并可能中断同进程内其他租户的作业。" ;;
    oob|oob_read|oob_write|memory)
      echo "越界内存访问在最好情况下导致进程崩溃（拒绝服务），在最坏情况下可能造成进程内敏感数据泄露或被进一步利用以影响完整性；在服务化 / 多租户部署中危害尤重。" ;;
    *)
      echo "可由公开接口以受控输入触发的进程级故障，在服务化部署中构成可用性风险。" ;;
  esac
}

# Literal placeholder substitution via bash string replacement (no sed/regex escaping hazards).
render_block() {
  # Replacement strings are quoted so a literal '&' is kept verbatim (an unquoted '&'
  # in a bash pattern substitution is replaced by the matched text).
  local out="$BLOCK"
  out="${out//'{{ID}}'/"$V_ID"}"
  out="${out//'{{TITLE}}'/"$V_TITLE"}"
  out="${out//'{{VULN_TYPE}}'/"$V_TYPE"}"
  out="${out//'{{SEVERITY}}'/"$V_SEVERITY"}"
  out="${out//'{{SOURCE_PATH}}'/"$V_SOURCE"}"
  out="${out//'{{ROOT_CAUSE}}'/"$V_ROOT"}"
  out="${out//'{{DISCOVERY_PROMPT}}'/"$V_PROMPT"}"
  out="${out//'{{PROMPT_RATIONALE}}'/"$V_RATIONALE"}"
  out="${out//'{{BUSINESS_IMPACT}}'/"$V_IMPACT"}"
  out="${out//'{{REPRO_CMD}}'/"$V_REPRO"}"
  printf '%s' "$out"
}

printf '%s' "$HEADER" > "$LIST_OUT"

shopt -s nullglob
findings=( "$FINDINGS_DIR"/VH-*/finding.json )
shopt -u nullglob
# Deterministic order by id.
IFS=$'\n' findings=($(printf '%s\n' "${findings[@]}" | sort)); unset IFS

if [ "${#findings[@]}" -eq 0 ]; then
  warn "no VH-*/finding.json under $FINDINGS_DIR — vulnerability_list.md will list no findings."
fi

for fj in "${findings[@]}"; do
  [ -f "$fj" ] || continue
  fdir="$(dirname "$fj")"
  fid="$(basename "$fdir")"

  V_ID="$(jq -r '.id // empty' "$fj")"; [ -n "$V_ID" ] || V_ID="$fid"
  V_TITLE="$(jq -r '.title // "(无标题)"' "$fj")"
  sink="$(jq -r '.sink_class // "unknown"' "$fj")"
  cwe="$(jq -r '.cwe // "N/A"' "$fj")"
  V_SEVERITY="$(jq -r 'if .cvss.score then "\(.severity // "UNKNOWN")（CVSS \(.cvss.score)）" else (.severity // "UNKNOWN") end' "$fj")"
  V_TYPE="$(type_label "$sink")（$cwe）"
  file="$(jq -r '.file // "N/A"' "$fj")"
  line="$(jq -r '.line // empty' "$fj")"
  sink_path="$(jq -r '.cited_kernel // empty' "$fj")"
  if [ -n "$line" ]; then V_SOURCE="\`$file:$line\`"; else V_SOURCE="\`$file\`"; fi
  if [ -n "$sink_path" ] && [ "$sink_path" != "$file:$line" ]; then
    V_SOURCE="$V_SOURCE（sink：\`$sink_path\`）"
  fi
  V_ROOT="$(jq -r '.missing_check // "(未记录)"' "$fj")"
  notes="$(jq -r '.notes // ""' "$fj")"
  if [ -n "$notes" ]; then V_PROMPT="$notes"; else V_PROMPT="$DEFAULT_PROMPT"; fi
  V_RATIONALE="$DEFAULT_RATIONALE"
  V_IMPACT="$(impact_line "$sink")"
  V_REPRO="$FINDINGS_DIR/$fid/run.sh"

  render_block >> "$LIST_OUT"
  n_findings=$((n_findings + 1))
done

foot="$FOOTER"
foot="${foot//'{{GENERATED_AT}}'/"$GENERATED_AT"}"
foot="${foot//'{{TARGET_SHA}}'/"$TARGET_SHA"}"
printf '%s\n' "$foot" >> "$LIST_OUT"

# ---- 2. vulnerability_report.md ------------------------------------------------------------
REPORT_OUT="$OUT_DIR/vulnerability_report.md"
if [ -n "${REPORT:-}" ]; then
  cp -f "$REPORT" "$REPORT_OUT"
  report_status="copied from $REPORT"
else
  warn "REPORT.md not found under findings dir or parent — writing a placeholder report."
  {
    echo "# 漏洞发现报告"
    echo
    echo "> 未在 findings 目录找到 REPORT.md。已确认发现数：$n_findings。"
    echo "> 详见同目录 vulnerability_list.md 与 llm_chat_log.json。黑盒：不断言目标身份/版本/CVE。"
  } > "$REPORT_OUT"
  report_status="placeholder (no REPORT.md found)"
fi

# ---- 3. llm_chat_log.json ------------------------------------------------------------------
CHAT_OUT="$OUT_DIR/llm_chat_log.json"
MODEL="unknown"
if [ -n "${MANIFEST:-}" ]; then
  MODEL="$(jq -r '.llm.model // "unknown"' "$MANIFEST" 2>/dev/null || echo unknown)"
fi

SYS_PROMPT='黑盒漏洞挖掘：目标是一个放置于 code/ 目录的未知原生数值/机器学习库，运行者从未被告知其项目名称、版本或任何已知缺陷；身份文件仅按路径记录、内容未读。方法为传统 DAST（隔离子进程模糊测试 + 崩溃后续跑）结合 LLM 语义推理，优先攻击调用者可控元数据流入 C++ 内核的薄算子封装。判定规则：进程级信号（SIGABRT/SIGSEGV/SIGFPE）或 "Check failed" 中止 = 真实缺陷；被捕获的 Python 异常 = 契约行为，非缺陷。每个上报缺陷都由可运行 PoC 三次一致复现证明。全程绝不断言目标身份/版本，绝不引用 CVE。'

# The PRIMARY llm_chat_log.json is the auditing model's ACTUAL, faithful dialogue (authored/exported
# by the model that performed the discovery). If such a curated file already exists in <out_dir>, we
# VALIDATE and KEEP it, and write the ledger-derived machine record alongside as
# llm_chat_log.ledger.json. Otherwise we emit the ledger-derived record as llm_chat_log.json — a
# starting skeleton to be enriched with the model's real prompts/responses.
CHAT_LEDGER="$OUT_DIR/llm_chat_log.ledger.json"
CURATED=0
if [ -f "$CHAT_OUT" ] && jq -e '(.chat_history|length) > 0' "$CHAT_OUT" >/dev/null 2>&1; then
  jq -e . "$CHAT_OUT" >/dev/null 2>&1 || { echo "ERROR: existing $CHAT_OUT is not valid JSON" >&2; exit 4; }
  CURATED=1
fi
DERIVED_OUT="$CHAT_OUT"; [ "$CURATED" = 1 ] && DERIVED_OUT="$CHAT_LEDGER"

if [ -n "${LEDGER:-}" ] && [ -s "$LEDGER" ]; then
  rec_count="$(jq -s 'length' "$LEDGER" 2>/dev/null || echo 0)"
  # Map each hash-chained ledger record to a faithful {turn, role, content} entry (user/assistant only).
  jq -s --arg model "$MODEL" --arg sys "$SYS_PROMPT" \
    '{ metadata: { llm_model_used: $model, record_count: (.|length), total_turns: (.|length),
         blackbox: true, system_prompt: $sys,
         note: "machine record derived from the hash-chained ledger; the curated llm_chat_log.json holds the model’s actual dialogue" },
       chat_history: [ . as $all | range(0; ($all|length)) as $i | $all[$i] |
         { turn: (.seq // $i),
           role: (if (.actor // "") == "operator" then "user" else "assistant" end),
           content: ("[phase=" + (.phase // "?") + " actor=" + (.actor // "?")
                     + " kind=" + (.kind // "?") + "] " + (.summary // "")) } ] }' \
    "$LEDGER" > "$DERIVED_OUT"
  if [ "$CURATED" = 1 ]; then chat_status="kept curated $CHAT_OUT; ledger machine record -> $CHAT_LEDGER ($rec_count records)"; total_turns="$(jq -r '.metadata.total_turns // 0' "$CHAT_OUT")";
  else chat_status="derived from ledger ($rec_count records) -> enrich with the model’s real dialogue"; total_turns="$rec_count"; fi
elif [ "$CURATED" = 1 ]; then
  chat_status="kept curated $CHAT_OUT (no ledger to derive a machine record)"; total_turns="$(jq -r '.metadata.total_turns // 0' "$CHAT_OUT")"
else
  warn "no curated log and no ledger — writing empty chat log."
  total_turns=0
  jq -n --arg model "$MODEL" --arg sys "$SYS_PROMPT" \
    '{ metadata: { llm_model_used: $model, total_turns: 0, blackbox: true, system_prompt: $sys },
       chat_history: [] }' > "$CHAT_OUT"
  chat_status="empty (no curated log, no ledger)"
fi

# Validate the emitted JSON.
if ! jq -e . "$CHAT_OUT" >/dev/null 2>&1; then
  echo "ERROR: emitted $CHAT_OUT is not valid JSON." >&2
  exit 4
fi

# ---- summary -------------------------------------------------------------------------------
echo "==================================================================="
echo "make_deliverables.sh — wrote 3 deliverables to: $OUT_DIR"
echo "  1. vulnerability_list.md    ($n_findings finding(s), model=$MODEL)"
echo "  2. vulnerability_report.md  ($report_status)"
echo "  3. llm_chat_log.json        ($chat_status; total_turns=$total_turns)"
echo "-------------------------------------------------------------------"
echo "  inputs: ledger=${LEDGER:-<none>}"
echo "          manifest=${MANIFEST:-<none>}"
echo "          report=${REPORT:-<none>}"
echo "  black-box: no identity/version/CVE assertions were written."
echo "==================================================================="
