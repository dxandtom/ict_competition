#!/usr/bin/env bash
# new_finding.sh — scaffold a findings/<id>/ proof package from the template.
#
# Layout per finding:
#   <findings>/findings/VH-NNNN/
#     finding.md        (from templates/finding.md, fields filled)
#     finding.json      (conforms to templates/finding.schema.json)
#     poc.{py,cc,bin}   (AI-generated reproducer — you add it)
#     run.sh            (one-command repro)
#     evidence/         (3 deterministic run logs proving the oracle fires)
#     oracle.json       (triage output from triage_crash.sh)
#
# A finding without poc + >=1 evidence log + oracle.confirmed==true stays UNCONFIRMED
# and is moved to <findings>/unconfirmed/.
#
# Usage: new_finding.sh <findings_dir> [--title T] [--sink S] [--severity SEV]
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
# Next id
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
# One-command repro for this finding. Fill in after you author the PoC.
set -euo pipefail
cd "$(dirname "$0")"
echo "TODO: invoke poc and assert the oracle fires (see finding.md)"
EOF
chmod +x "$DIR/run.sh"

[ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase poc --actor new_finding.sh \
  --kind artifact --summary "scaffolded $ID ($TITLE)" >/dev/null 2>&1 || true
echo "$DIR"
