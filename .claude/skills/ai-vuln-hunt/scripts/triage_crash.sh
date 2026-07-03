#!/usr/bin/env bash
# triage_crash.sh — 对崩溃/oracle 日志进行分类，计算一个在重构后保持稳定的 stack_hash
# 用于去重，并（可选地）最小化触发崩溃的输入。
#
# 可识别：ASAN/UBSAN/MSAN 报告、SIGSEGV/SIGFPE/SIGABRT、CHECK/assert/abort、
# 未捕获的 Python 异常，以及 Python-oracle / 差分测试违规。
# 没有任何 oracle 匹配时 => evidence_type 为 "none"，该发现保持 UNCONFIRMED 状态。
#
# 用法: triage_crash.sh <log_file> [--input CRASH_INPUT] [--binary BIN] [--minimize]
# 将一个 JSON triage 对象打印到 stdout。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${1:?usage: triage_crash.sh <log_file> [--input F] [--binary B] [--minimize]}"; shift
INPUT=""; BIN=""; MIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --input) INPUT="$2"; shift 2;;
    --binary) BIN="$2"; shift 2;;
    --minimize) MIN=1; shift;;
    *) shift;;
  esac
done
command -v jq >/dev/null 2>&1 || { echo '{"error":"jq required"}'; exit 2; }
[ -f "$LOG" ] || { echo "{\"error\":\"no log: $LOG\"}"; exit 2; }
TXT="$(cat "$LOG")"

evidence="none"; sink="other"; cwe=""; severity="UNKNOWN"; signature=""
match(){ printf '%s' "$TXT" | grep -Eiq "$1"; }

if match 'ERROR: AddressSanitizer: heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow'; then
  evidence="asan"; sink="oob_rw"; cwe="CWE-787/125"; severity="HIGH"; signature="asan-buffer-overflow"
elif match 'AddressSanitizer: heap-use-after-free'; then
  evidence="asan"; sink="use_after_free"; cwe="CWE-416"; severity="HIGH"; signature="asan-uaf"
elif match 'AddressSanitizer'; then
  evidence="asan"; sink="memory"; cwe="CWE-119"; severity="HIGH"; signature="asan-other"
elif match 'runtime error:.*signed integer overflow|runtime error:.*shift'; then
  evidence="ubsan"; sink="int_overflow"; cwe="CWE-190"; severity="MEDIUM"; signature="ubsan-int-overflow"
elif match 'UndefinedBehaviorSanitizer|runtime error:'; then
  evidence="ubsan"; sink="undefined_behavior"; cwe="CWE-758"; severity="MEDIUM"; signature="ubsan-other"
elif match 'MemorySanitizer: use-of-uninitialized'; then
  evidence="msan"; sink="uninit"; cwe="CWE-457"; severity="MEDIUM"; signature="msan-uninit"
elif match 'SIGSEGV|Segmentation fault'; then
  evidence="signal_segv"; sink="oob_rw"; cwe="CWE-476/787"; severity="HIGH"; signature="signal_segv"
elif match 'SIGFPE|Floating point exception|division by zero'; then
  evidence="signal_fpe"; sink="availability"; cwe="CWE-369"; severity="MEDIUM"; signature="signal_fpe"
elif match 'SIGABRT|Aborted|abort\(\)|terminate called'; then
  evidence="abort"; sink="availability"; cwe="CWE-617"; severity="MEDIUM"; signature="abort"
elif match 'Check failed:|CHECK_|F[0-9].* Check failed|assert(ion)? .*failed'; then
  evidence="check_assert"; sink="availability"; cwe="CWE-617"; severity="MEDIUM"; signature="check_assert"
elif match 'DIFFERENTIAL-MISMATCH'; then
  evidence="differential_mismatch"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="differential_mismatch"
elif match 'METAMORPHIC-VIOLATION'; then
  evidence="metamorphic_violation"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="metamorphic_violation"
elif match 'INVARIANT-VIOLATION|ORACLE-VIOLATION'; then
  evidence="invariant_violation"; sink="contract"; cwe="CWE-682"; severity="MEDIUM"; signature="invariant_violation"
elif match 'Traceback \(most recent call last\)'; then
  # 未捕获的 Python 异常 —— 仅当处于绝不应抛出异常的代码中才计入（由审查者判定）。
  evidence="uncaught_exception"; sink="availability"; cwe="CWE-248"; severity="LOW"; signature="py-exception"
fi

# 提取顶部的应用帧（去除地址、行号、sanitizer/解释器粘合代码）。
# 将 C++ 帧的源信息锚定到行尾，使得带空格的签名不会被截断。
FRAMES="$(printf '%s' "$TXT" \
  | grep -aE '#[0-9]+ ' \
  | sed -E 's/0x[0-9a-fA-F]+//g; s/\+0x[0-9a-fA-F]+//g; s/:[0-9]+:[0-9]+//g; s/:[0-9]+//g' \
  | grep -avE 'libclang_rt|sanitizer|__asan|__ubsan|_PyEval|ceval|atheris|libfuzzer|llvm|/usr/lib' \
  | grep -aoE 'in [^[:cntrl:]]+$' \
  | head -3 || true)"
# stack_hash 是从“路径无关”的帧（文件路径缩减为 basename）计算得出的，因此它在
# 不同机器/工作目录/构建根之间保持稳定 —— 只有符号+basename 的标识才重要。带路径的
# 原始 FRAMES 被保留下来用于显示，以及用于下面的 code/ 成员检测。
HASH_FRAMES="$(printf '%s' "$FRAMES" | sed -E 's#[^ ]*/([^/ ]+)$#\1#')"

# 非 sanitizer 构建（如 pip 包）不打印 "#N" 原生回溯帧，而是打印 glog 风格的源位置
# （例如 "F tensorflow/.../threadpool.cc:100] Check failed: ..."）或普通的 "path.ext:line"。
# 提取这些源位置，并仅保留其文件确实存在于目标代码树（CODE_ROOT，默认 ./code）下的那些 ——
# 这样 CHECK-fail/abort 的证据也能被证明确实位于 code/ 内部，而不依赖 ASAN 回溯格式。
CODE_ROOT="${CODE_ROOT:-code}"
CODE_SRCLOCS="$(printf '%s' "$TXT" | grep -aoE '[A-Za-z0-9_./-]+\.(cc|cpp|cxx|h|hpp|py):[0-9]+' | sort -u \
  | while IFS= read -r loc; do fp="${loc%:*}"; case "$fp" in */*) { [ -f "$CODE_ROOT/$fp" ] || [ -f "$fp" ]; } && echo "$loc";; esac; done | head -3 || true)"

# 若没有原生 #N 帧但有位于 code/ 内的源位置（CHECK-fail 情形），则用后者计算 stack_hash。
if [ -z "$FRAMES" ] && [ -n "$CODE_SRCLOCS" ]; then
  HASH_FRAMES="$(printf '%s' "$CODE_SRCLOCS" | sed -E 's#.*/##')"
fi
STACK_HASH="$(printf '%s' "$HASH_FRAMES" | sha256sum | awk '{print $1}')"
# 用于显示的帧：优先原生帧，否则用 code/ 内的源位置。
DISPLAY_FRAMES="$FRAMES"; [ -z "$DISPLAY_FRAMES" ] && DISPLAY_FRAMES="$CODE_SRCLOCS"

# Gate 策略因证据类别而异：
#  - 内存/信号/abort/check 类 oracle 必须在 code/ 内部有一个原生崩溃帧（不能仅在 harness 中）。
#  - 契约类 oracle（invariant/differential/metamorphic）在测试文件中抛出一个普通的
#    AssertionError：它们没有原生帧，因此改为基于（记录的输入 + 候选中引用的内核
#    file:line + 固定种子的确定性重放）来 gate —— 由 confirm_finding.sh 强制执行。
case "$evidence" in
  asan|ubsan|msan|signal_segv|signal_fpe|abort|check_assert) REQ_NATIVE=true;;
  *) REQ_NATIVE=false;;
esac
HAS_CODE_FRAME=false
printf '%s' "$FRAMES" | grep -q 'code/' && HAS_CODE_FRAME=true
[ -n "$CODE_SRCLOCS" ] && HAS_CODE_FRAME=true

# 如有请求且可行，则最小化触发崩溃的输入。
MIN_INPUT=""
if [ "$MIN" = 1 ] && [ -n "$INPUT" ] && [ -f "$INPUT" ] && [ -n "$BIN" ] && [ -x "$BIN" ]; then
  MINOUT="${INPUT}.min"
  if "$BIN" -minimize_crash=1 -runs=20000 -exact_artifact_path="$MINOUT" "$INPUT" >/dev/null 2>&1; then
    MIN_INPUT="$MINOUT"
  elif command -v afl-tmin >/dev/null 2>&1; then
    afl-tmin -i "$INPUT" -o "$MINOUT" -- "$BIN" @@ >/dev/null 2>&1 && MIN_INPUT="$MINOUT" || true
  fi
fi

jq -n --arg ev "$evidence" --arg sink "$sink" --arg cwe "$cwe" --arg sev "$severity" \
  --arg sig "$signature" --arg sh "$STACK_HASH" --arg frames "$DISPLAY_FRAMES" \
  --arg input "$INPUT" --arg min "$MIN_INPUT" --arg log "$LOG" \
  --argjson reqnative "$REQ_NATIVE" --argjson codeframe "$HAS_CODE_FRAME" \
  '{evidence_type:$ev, sink_class:$sink, cwe:$cwe, severity:$sev, signature:$sig,
    stack_hash:$sh, top_frames:($frames|split("\n")|map(select(length>0))),
    crash_input:$input, minimized_input:$min, log:$log,
    requires_native_frame:$reqnative, has_code_frame:$codeframe,
    confirmed:(($ev!="none") and ((($reqnative|not)) or $codeframe))}'

[ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "${FINDINGS_DIR:-$(dirname "$LOG")}" \
  --phase triage --actor triage_crash.sh --kind decision \
  --summary "triage: $signature stack=$STACK_HASH" --blob "$LOG" >/dev/null 2>&1 || true
