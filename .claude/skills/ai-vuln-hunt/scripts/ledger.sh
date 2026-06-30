#!/usr/bin/env bash
# ledger.sh — append-only, hash-chained reproducibility ledger + env manifest.
#
# BLACK-BOX NOTE: This script records the AI interaction process. It never reads
# host-identity files (VERSION/CHANGELOG/RELEASE/SECURITY/NOTICE/AUTHORS/.git tags).
# Large blobs are content-addressed (stored under findings/blobs/<sha256>) and only
# their sha256 is inlined, so the ledger stays small on a multi-MLOC target.
#
# Usage:
#   ledger.sh init  <findings_dir> <code_dir>
#   ledger.sh append <findings_dir> --phase P --actor A --kind K [--lens L] \
#                    [--summary S] [--blob FILE]... [--kv key=val]...
#   ledger.sh verify <findings_dir>
#
# Every other script in this skill calls `ledger.sh append` for each tool_call.
set -euo pipefail

sha256() { sha256sum "$1" | awk '{print $1}'; }
sha256_str() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

die() { echo "ledger.sh: $*" >&2; exit 2; }
need_jq() { command -v jq >/dev/null 2>&1 || die "jq is required"; }

cmd="${1:-}"; shift || true
need_jq

case "$cmd" in
init)
  FIND="${1:?findings_dir}"; CODE="${2:?code_dir}"
  mkdir -p "$FIND/blobs" "$FIND/raw" "$FIND/candidates" "$FIND/sbom" "$FIND/findings" "$FIND/unconfirmed"
  LED="$FIND/ledger.jsonl"
  [ -f "$LED" ] || : > "$LED"
  # Content-identity of the target: hash a manifest of SOURCE files only — never read binaries,
  # build dirs, datasets, or host-identity files (those are excluded by the extension allowlist
  # and recorded by path only). Streamed + parallel + time-boxed so it scales to multi-GB trees.
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
  # Record host-identity files by PATH ONLY (never read/hash their contents).
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
  # Model id is pinned for the record but the run does NOT claim bit-reproducible LLM output:
  # see env_manifest.reproducibility_note. Override the recorded id via AIVH_MODEL.
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
  echo "initialized ledger at $LED (session $SESSION, tree $TREE)"
  ;;

append)
  FIND="${1:?findings_dir}"; shift
  LED="$FIND/ledger.jsonl"; [ -f "$LED" ] || die "run 'ledger.sh init' first"
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
        [ -f "$f" ] || { echo "ledger.sh: blob not found: $f" >&2; continue; }
        h="$(sha256 "$f")"; dst="$FIND/blobs/$h"
        if [ -e "$dst" ]; then
          [ "$(sha256 "$dst")" = "$h" ] || echo "ledger.sh: WARN blob hash collision at $dst" >&2
        else cp "$f" "$dst" 2>/dev/null || true; fi
        BLOBS="$(echo "$BLOBS" | jq --arg p "$f" --arg h "$h" '. + [{path:$p, sha256:$h}]')"
        ;;
      --kv) k="${2%%=*}"; v="${2#*=}"; shift 2
        KV="$(echo "$KV" | jq --arg k "$k" --arg v "$v" '.[$k]=$v')";;
      *) die "unknown arg: $1";;
    esac
  done
  # Black-box guard the summary before committing it to the permanent record.
  GUARD="ok"
  if [ -x "$(dirname "$0")/blackbox_guard.sh" ] && [ -n "$SUMMARY" ]; then
    if ! printf '%s' "$SUMMARY" | "$(dirname "$0")/blackbox_guard.sh" scan-stdin >/dev/null 2>&1; then
      GUARD="leak_blocked"; SUMMARY="[REDACTED: black-box guard blocked identity-revealing text]"
    fi
  fi
  # Read-modify-append must be atomic: parallel SCA/SAST stages each append concurrently.
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
  [ -f "$LED" ] || die "no ledger"
  prev=""; n=0; bad=0
  while IFS= read -r line; do
    n=$((n+1))
    payload="$(echo "$line" | jq -c 'del(.record_id,.prev_id,.payload_sha256,.chain_sha256)')"
    psha="$(sha256_str "$payload")"
    want_psha="$(echo "$line" | jq -r '.payload_sha256')"
    want_csha="$(echo "$line" | jq -r '.chain_sha256')"
    csha="$(sha256_str "${prev}${psha}")"
    if [ "$psha" != "$want_psha" ] || [ "$csha" != "$want_csha" ]; then
      echo "TAMPER at record $n (seq $(echo "$line" | jq -r .seq))" >&2; bad=1; break
    fi
    prev="$want_csha"
  done < "$LED"
  if [ "$bad" = 0 ]; then echo "OK: $n records, chain intact"; else exit 1; fi
  ;;

*) die "usage: ledger.sh {init|append|verify} ...";;
esac
