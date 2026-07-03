#!/usr/bin/env bash
# ledger.sh — 仅追加、哈希链式的可复现性账本 + 环境清单。
#
# 黑盒说明：本脚本记录 AI 交互过程。它从不读取宿主身份文件
# （VERSION/CHANGELOG/RELEASE/SECURITY/NOTICE/AUTHORS/.git 标签）。
# 大型数据块按内容寻址（存储在 findings/blobs/<sha256> 下），账本中只内联
# 其 sha256，因此在多兆行（multi-MLOC）目标上账本仍保持很小。
#
# 用法：
#   ledger.sh init  <findings_dir> <code_dir>
#   ledger.sh append <findings_dir> --phase P --actor A --kind K [--lens L] \
#                    [--summary S] [--blob FILE]... [--kv key=val]...
#   ledger.sh verify <findings_dir>
#
# 本技能中的每个其他脚本都会对每次 tool_call 调用 `ledger.sh append`。
set -euo pipefail

sha256() { sha256sum "$1" | awk '{print $1}'; }
sha256_str() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

die() { echo "ledger.sh: $*" >&2; exit 2; }
need_jq() { command -v jq >/dev/null 2>&1 || die "需要 jq"; }

cmd="${1:-}"; shift || true
need_jq

case "$cmd" in
init)
  FIND="${1:?findings_dir}"; CODE="${2:?code_dir}"
  mkdir -p "$FIND/blobs" "$FIND/raw" "$FIND/candidates" "$FIND/sbom" "$FIND/findings" "$FIND/unconfirmed"
  LED="$FIND/ledger.jsonl"
  [ -f "$LED" ] || : > "$LED"
  # 目标的内容身份：仅对源文件清单做哈希——绝不读取二进制文件、
  # 构建目录、数据集或宿主身份文件（这些被扩展名白名单排除，
  # 仅按路径记录）。流式 + 并行 + 限时处理，因此可扩展到多 GB 的目录树。
  MANIFEST="$FIND/target_tree_manifest.txt"
  : > "$MANIFEST"
  ( cd "$CODE" && timeout 600 bash -c '
      find . -type f \
        ! -path "*/.git/*" ! -path "*/bazel-*" ! -path "*/node_modules/*" \
        ! -path "*/build/*" ! -path "*/.sca/*" ! -path "*/.git" \
        -size -5M \
        \( -name "*.py" -o -name "*.pyi" -o -name "*.c" -o -name "*.cc" -o -name "*.cpp" \
           -o -name "*.cxx" -o -name "*.cu" -o -name "*.cuh" -o -name "*.h" -o -name "*.hh" \
           -o -name "*.hpp" -o -name "*.hxx" -o -name "*.proto" -o -name "*.java" -o -name "*.go" \
           -o -name "*.rs" -o -name "*.js" -o -name "*.ts" -o -name "*.bzl" -o -name "BUILD*" \
           -o -name "WORKSPACE*" -o -name "CMakeLists.txt" -o -name "*.cmake" -o -name "Makefile*" \
           -o -name "*.mk" -o -name "*.sh" \) -print0 \
      | xargs -0 -P"$(nproc 2>/dev/null || echo 4)" -n 64 sha256sum 2>/dev/null \
      | sed "s#  \./#  #"' ) | sort > "$MANIFEST" || true
  TREE="$(sha256sum "$MANIFEST" | awk '{print $1}')"
  FILE_COUNT="$(wc -l < "$MANIFEST" | tr -d ' ')"
  # 仅按路径记录宿主身份文件（绝不读取/哈希其内容）。
  ID_FILES="$(cd "$CODE" && find . -maxdepth 2 -type f ! -path '*/third_party/*' \
      ! -path '*/external/*' ! -path '*/vendor/*' \
      \( -iname 'VERSION' -o -iname 'VERSION.*' -o -iname 'version.bazel' -o -iname 'CHANGELOG*' \
         -o -iname 'CHANGES' -o -iname 'CHANGES.*' -o -iname 'RELEASE*' -o -iname 'NEWS' \
         -o -iname 'HISTORY*' -o -iname 'SECURITY*' -o -iname 'NOTICE*' -o -iname 'AUTHORS' \
         -o -iname 'CONTRIBUTORS' -o -iname 'MAINTAINERS' \) 2>/dev/null \
      | sed 's#^\./#code/#' | sort | jq -R . 2>/dev/null | jq -cs . 2>/dev/null || echo '[]')"
  [ -n "$ID_FILES" ] || ID_FILES='[]'
  SESSION="$(sha256_str "$(now)-$$-$RANDOM")"
  MAN="$FIND/env_manifest.json"
  # 模型 id 已为本记录固定，但本次运行并不声称 LLM 输出可按位复现：
  # 参见 env_manifest.reproducibility_note。可通过 AIVH_MODEL 覆盖所记录的 id。
  MODEL_ID="${AIVH_MODEL:-unset-record-actual-model-id-here}"
  toolver() { command -v "$1" >/dev/null 2>&1 && { "$@" 2>&1 | head -1; } || echo "absent"; }
  jq -n \
    --arg ts "$(now)" --arg session "$SESSION" --arg tree "$TREE" \
    --argjson files "${FILE_COUNT:-0}" --arg os "$(uname -a)" \
    --arg py "$(toolver python3 --version)" \
    --arg clang "$(toolver clang --version)" \
    --arg gcc "$(toolver gcc --version)" \
    --arg go "$(toolver go version)" \
    --arg semgrep "$(toolver semgrep --version)" \
    --arg bandit "$(toolver bandit --version)" \
    --arg cppcheck "$(toolver cppcheck --version)" \
    --arg osv "$(toolver osv-scanner --version)" \
    --arg syft "$(toolver syft version)" \
    --arg model "$MODEL_ID" \
    --argjson idfiles "$ID_FILES" \
    '{schema:"manifest-1.0", created:$ts, session_id:$session,
      target_tree_sha256:$tree, source_file_count:$files,
      target_tree_manifest:"target_tree_manifest.txt", os:$os,
      tools:{python:$py, clang:$clang, gcc:$gcc, go:$go, semgrep:$semgrep,
             bandit:$bandit, cppcheck:$cppcheck, "osv-scanner":$osv, syft:$syft},
      llm:{model:$model, temperature:0},
      reproducibility_note:"Tool inputs/outputs are content-addressed and replay deterministically. LLM calls are NOT bit-reproducible (no exposed sampling seed) but are fully logged (prompt+response blobs by sha256) and re-runnable; findings are PoC-gated, so a confirmed bug reproduces deterministically via its PoC regardless of which LLM run surfaced it.",
      identity_files_seen_but_unread:$idfiles}' > "$MAN"
  echo "$SESSION" > "$FIND/.session_id"
  echo "已在 $LED 初始化账本（会话 $SESSION，目录树 $TREE）"
  ;;

append)
  FIND="${1:?findings_dir}"; shift
  LED="$FIND/ledger.jsonl"; [ -f "$LED" ] || die "请先运行 'ledger.sh init'"
  SESSION="$(cat "$FIND/.session_id" 2>/dev/null || echo unknown)"
  PHASE=""; ACTOR=""; KIND="note"; LENS=""; SUMMARY=""
  BLOBS="[]"; KV="{}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --phase) PHASE="$2"; shift 2;;
      --actor) ACTOR="$2"; shift 2;;
      --kind)  KIND="$2"; shift 2;;
      --lens)  LENS="$2"; shift 2;;
      --summary) SUMMARY="$2"; shift 2;;
      --blob)
        f="$2"; shift 2
        [ -f "$f" ] || { echo "ledger.sh: 未找到数据块：$f" >&2; continue; }
        h="$(sha256 "$f")"; dst="$FIND/blobs/$h"
        if [ -e "$dst" ]; then
          [ "$(sha256 "$dst")" = "$h" ] || echo "ledger.sh: 警告 在 $dst 处发生数据块哈希冲突" >&2
        else cp "$f" "$dst" 2>/dev/null || true; fi
        BLOBS="$(echo "$BLOBS" | jq --arg p "$f" --arg h "$h" '. + [{path:$p, sha256:$h}]')"
        ;;
      --kv) k="${2%%=*}"; v="${2#*=}"; shift 2
        KV="$(echo "$KV" | jq --arg k "$k" --arg v "$v" '.[$k]=$v')";;
      *) die "未知参数：$1";;
    esac
  done
  # 在将摘要提交到永久记录之前，对其进行黑盒守护检查。
  GUARD="ok"
  if [ -x "$(dirname "$0")/blackbox_guard.sh" ] && [ -n "$SUMMARY" ]; then
    if ! printf '%s' "$SUMMARY" | "$(dirname "$0")/blackbox_guard.sh" scan-stdin >/dev/null 2>&1; then
      GUARD="leak_blocked"; SUMMARY="[REDACTED: black-box guard blocked identity-revealing text]"
    fi
  fi
  # 读取-修改-追加必须是原子操作：并行的 SCA/SAST 阶段各自并发追加。
  exec 9>"$LED.lock"
  if command -v flock >/dev/null 2>&1; then flock 9; fi
  PREV_CHAIN="$(tail -1 "$LED" 2>/dev/null | jq -r '.chain_sha256 // ""' 2>/dev/null || echo "")"
  PREV_ID="$(tail -1 "$LED" 2>/dev/null | jq -r '.record_id // ""' 2>/dev/null || echo "")"
  SEQ="$(wc -l < "$LED" | tr -d ' ')"
  PAYLOAD="$(jq -cn \
    --arg ts "$(now)" --arg session "$SESSION" --argjson seq "$SEQ" \
    --arg phase "$PHASE" --arg actor "$ACTOR" --arg kind "$KIND" \
    --arg lens "$LENS" --arg summary "$SUMMARY" --arg guard "$GUARD" \
    --argjson blobs "$BLOBS" --argjson kv "$KV" \
    '{ts:$ts, session_id:$session, seq:$seq, phase:$phase, actor:$actor,
      kind:$kind, lens:$lens, summary:$summary, bb_guard:$guard,
      blobs:$blobs, data:$kv}')"
  PAYLOAD_SHA="$(sha256_str "$PAYLOAD")"
  CHAIN_SHA="$(sha256_str "${PREV_CHAIN}${PAYLOAD_SHA}")"
  REC_ID="$(sha256_str "${SESSION}-${SEQ}-${PAYLOAD_SHA}")"
  echo "$PAYLOAD" | jq -c \
    --arg rid "$REC_ID" --arg pid "$PREV_ID" \
    --arg psha "$PAYLOAD_SHA" --arg csha "$CHAIN_SHA" \
    '{record_id:$rid, prev_id:$pid} + . + {payload_sha256:$psha, chain_sha256:$csha}' >> "$LED"
  echo "$REC_ID"
  ;;

verify)
  FIND="${1:?findings_dir}"; LED="$FIND/ledger.jsonl"
  [ -f "$LED" ] || die "无账本"
  prev=""; n=0; bad=0
  while IFS= read -r line; do
    n=$((n+1))
    payload="$(echo "$line" | jq -c 'del(.record_id,.prev_id,.payload_sha256,.chain_sha256)')"
    psha="$(sha256_str "$payload")"
    want_psha="$(echo "$line" | jq -r '.payload_sha256')"
    want_csha="$(echo "$line" | jq -r '.chain_sha256')"
    csha="$(sha256_str "${prev}${psha}")"
    if [ "$psha" != "$want_psha" ] || [ "$csha" != "$want_csha" ]; then
      echo "TAMPER 于记录 $n（seq $(echo "$line" | jq -r .seq)）" >&2; bad=1; break
    fi
    prev="$want_csha"
  done < "$LED"
  if [ "$bad" = 0 ]; then echo "OK：$n 条记录，链完整"; else exit 1; fi
  ;;

*) die "用法：ledger.sh {init|append|verify} ...";;
esac
