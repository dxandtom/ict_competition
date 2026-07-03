#!/usr/bin/env bash
# new_finding.sh — 从模板生成 findings/<id>/ 证明包脚手架。
#
# 每个发现的目录结构：
#   <findings>/findings/VH-NNNN/
#     finding.md        （由 templates/finding.md 生成，字段已填充）
#     finding.json      （符合 templates/finding.schema.json）
#     poc.{py,cc,bin}   （AI 生成的复现器——由你添加）
#     run.sh            （一条命令完成复现）
#     evidence/         （3 条确定性运行日志，证明 oracle 触发）
#     oracle.json       （来自 triage_crash.sh 的分类输出）
#
# 缺少 poc、至少 1 条 evidence 日志或 oracle.confirmed==true 的发现将保持为 UNCONFIRMED 状态，
# 并被移动到 <findings>/unconfirmed/。
#
# 用法： new_finding.sh <findings_dir> [--title T] [--sink S] [--severity SEV]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
FIND="${1:?usage: new_finding.sh <findings_dir> [--title T] [--sink S] [--severity SEV]}"; shift
TITLE="untitled"; SINK="other"; SEV="UNKNOWN"
while [ $# -gt 0 ]; do
  case "$1" in
    --title) TITLE="$2"; shift 2;;
    --sink) SINK="$2"; shift 2;;
    --severity) SEV="$2"; shift 2;;
    *) shift;;
  esac
done
mkdir -p "$FIND/findings"
# 下一个 id
N=1
while [ -d "$FIND/findings/VH-$(printf '%04d' "$N")" ]; do N=$((N+1)); done
ID="VH-$(printf '%04d' "$N")"
DIR="$FIND/findings/$ID"
mkdir -p "$DIR/evidence"

TMPL_MD="$SKILL/templates/finding.md"
if [ -f "$TMPL_MD" ]; then
  sed -e "s/{{ID}}/$ID/g" -e "s/{{TITLE}}/$TITLE/g" -e "s/{{SINK}}/$SINK/g" \
      -e "s/{{SEVERITY}}/$SEV/g" "$TMPL_MD" > "$DIR/finding.md"
else
  printf '# %s — %s\n\nstatus: UNCONFIRMED\n' "$ID" "$TITLE" > "$DIR/finding.md"
fi

jq -n --arg id "$ID" --arg title "$TITLE" --arg sink "$SINK" --arg sev "$SEV" \
  '{schema:"finding-1.0", id:$id, title:$title, sink_class:$sink, severity:$sev,
    status:"UNCONFIRMED", cwe:"", file:"", line:0,
    entry_point:"", taint_path:[], missing_check:"",
    poc:{path:"", kind:""}, evidence:[], oracle:{},
    cited_kernel:"", failing_input:"", stubbed_symbols:[],
    needs_real_build_confirmation:false,
    cvss:{score:0, vector:""}, references:[], notes:""}' > "$DIR/finding.json"

cat > "$DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
# 此发现的一条命令复现脚本。在编写完 PoC 后填写此处。
set -euo pipefail
cd "$(dirname "$0")"
echo "TODO: 调用 poc 并断言 oracle 触发（见 finding.md）"
EOF
chmod +x "$DIR/run.sh"

[ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase poc --actor new_finding.sh \
  --kind artifact --summary "scaffolded $ID ($TITLE)" >/dev/null 2>&1 || true
echo "$DIR"
