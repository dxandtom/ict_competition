#!/usr/bin/env bash
# build_cpp_fuzzer.sh — 编译单个翻译单元（translation unit）+ 一个 libFuzzer harness，
# 启用 ASAN/UBSAN，无需完整的 Bazel 构建。在循环中根据链接器的
# "undefined reference" 错误自动生成弱链接（weak link）桩，直到该单元链接成功。
#
# 黑盒说明：仅对 code/ 下的源码路径进行操作。不涉及任何身份文件。
#
# 用法: build_cpp_fuzzer.sh <harness.cc> <out_binary> <unit1.cc> [unit2.cc ...] \
#                            [-- extra clang args like -Icode/include]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${1:?usage: build_cpp_fuzzer.sh <harness.cc> <out_bin> <unit.cc>... [-- args]}"; shift
OUTBIN="${1:?out_binary}"; shift
UNITS=(); EXTRA=()
seen_dd=0
for a in "$@"; do
  if [ "$a" = "--" ]; then seen_dd=1; continue; fi
  if [ "$seen_dd" = 1 ]; then EXTRA+=("$a"); else UNITS+=("$a"); fi
done
FIND="${FINDINGS_DIR:-$(dirname "$OUTBIN")}"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase dast --actor build_cpp_fuzzer.sh "$@" >/dev/null 2>&1 || true; }

CXX="${CXX:-clang++}"
command -v "$CXX" >/dev/null 2>&1 || { echo "[build] 未找到 $CXX；请尝试安装 gcc/clang" >&2; exit 1; }
SAN="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1"
STUBS="$(mktemp --suffix=.cc)"; : > "$STUBS"
STUBBED_SYMS=()                          # 每个弱桩符号的名称（溯源用！）
WORK="$(dirname "$OUTBIN")"; mkdir -p "$WORK"

echo "[build] harness=$HARNESS units=${UNITS[*]} extra=${EXTRA[*]}" >&2
attempt=0; MAX=25
while :; do
  attempt=$((attempt+1))
  LOG="$WORK/link_attempt_${attempt}.log"
  if "$CXX" $SAN "${EXTRA[@]}" "$HARNESS" "${UNITS[@]}" "$STUBS" -o "$OUTBIN" 2>"$LOG"; then
    echo "[build] 经过 $attempt 次尝试后链接成功 -> $OUTBIN" >&2
    # 持久化保存桩的溯源信息：confirm_finding.sh 要求污点路径上不存在任何被打桩的符号，
    # 并在被打桩的 PoC 能够被标记为 CONFIRMED 之前，强制在真实构建上重新确认。
    STUBS_JSON="$OUTBIN.stubs.json"
    printf '%s\n' "${STUBBED_SYMS[@]:-}" | jq -R . 2>/dev/null | jq -cs 'map(select(length>0))' \
      > "$STUBS_JSON" 2>/dev/null || echo '[]' > "$STUBS_JSON"
    n="$(jq 'length' "$STUBS_JSON" 2>/dev/null || echo 0)"
    if [ "$n" -gt 0 ]; then
      echo "[build] WARNING: 链接时使用了 $n 个弱桩（WEAK STUB）: $STUBS_JSON" >&2
      echo "[build] 经过某个桩到达的崩溃可能是构建产物，而非真实的 bug。" >&2
      echo "[build] 请在 finding.json 中根据此文件设置 stubbed_symbols，并设置 needs_real_build_confirmation=true" >&2
      echo "[build] 直到你针对真实构建（build_sanitized.sh bazel）重新确认最小化输入为止。" >&2
    fi
    led --kind tool_call --summary "built libfuzzer harness ($attempt attempts, $n stubs)" --blob "$OUTBIN" || true
    led --kind artifact --summary "stub provenance" --blob "$STUBS_JSON" || true
    break
  fi
  # 提取未定义符号并生成弱桩。
  NEW="$(grep -oE 'undefined reference to .?[A-Za-z_][A-Za-z0-9_:]*' "$LOG" \
        | sed -E "s/.*to .?//" | tr -d \"\047\"\140 | sort -u || true)"
  if [ -z "$NEW" ]; then
    echo "[build] 链接失败且没有可解析的未定义引用；详见 $LOG" >&2
    cat "$LOG" >&2; exit 1
  fi
  added=0
  while IFS= read -r sym; do
    [ -z "$sym" ] && continue
    grep -qF "/* STUB: $sym */" "$STUBS" 2>/dev/null && continue
    {
      echo "/* STUB: $sym */"
      echo "extern \"C\" __attribute__((weak)) void ${sym}() {}"
    } >> "$STUBS"
    STUBBED_SYMS+=("$sym")
    added=$((added+1))
  done <<< "$NEW"
  echo "[build] 第 $attempt 次尝试: 新增了 $added 个桩" >&2
  if [ "$attempt" -ge "$MAX" ]; then echo "[build] 在 $MAX 次尝试后放弃" >&2; exit 1; fi
done

echo "[build] 运行: $OUTBIN -runs=200000 -max_total_time=120 corpus/" >&2
echo "[build] (设置 ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1)" >&2
