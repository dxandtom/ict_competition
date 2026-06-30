#!/usr/bin/env bash
# run_atheris.sh — 运行 Python Atheris harness，并正确接入原生 sanitizer。
#
# 关于原生覆盖率的关键事实：对 ASAN 运行时执行 LD_PRELOAD 并不会插桩一个
# 已编译完成的 .so。ASAN 只能检测使用 -fsanitize=address 编译的代码中的内存破坏。
# 针对一个标准的预编译原生扩展，preload 几乎什么都捕获不到（仅有少数可拦截的
# libc 调用）。要获得真正的原生内存安全证明，你必须加载目标的“已插桩”构建——
# 用 scripts/build_sanitized.sh 重新构建它（bazel --config=asan，或单个已加 sanitizer 的
# .so），并将 PYTHONPATH 指向它。本脚本会验证插桩情况，并拒绝在一个未插桩的模块上
# *声称*已具备原生覆盖率。
#
# 子命令：  run_atheris.sh check-instrumented <module-or-.so>   # 若已 ASAN 插桩则退出码为 0
#
# 黑盒说明：仅针对 code/ 运行 AI 生成的 harness；不使用任何身份文件。
#
# 用法: run_atheris.sh <harness.py> [--time SECONDS] [--corpus DIR]
#                       [--require-instrumented <module-or-.so>] [-- atheris/libfuzzer args]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# 某个共享对象 / 可导入模块是否包含 ASAN 插桩？
so_is_instrumented() { # $1 = .so 的路径
  local so="$1"; [ -f "$so" ] || return 2
  if command -v nm >/dev/null 2>&1; then nm -D "$so" 2>/dev/null | grep -q '__asan_init' && return 0; fi
  if command -v objdump >/dev/null 2>&1; then objdump -T "$so" 2>/dev/null | grep -q '__asan' && return 0; fi
  command -v strings >/dev/null 2>&1 && strings "$so" 2>/dev/null | grep -q '__asan_init' && return 0
  return 1
}
module_so_path() { # $1 = python 模块名 -> 打印 .so 路径
  python3 - "$1" <<'PY' 2>/dev/null || true
import importlib.util,sys
s=importlib.util.find_spec(sys.argv[1])
print(s.origin if s and s.origin else "")
PY
}

if [ "${1:-}" = "check-instrumented" ]; then
  arg="${2:?usage: run_atheris.sh check-instrumented <module-or-.so>}"
  so="$arg"; case "$arg" in *.so) :;; *) so="$(module_so_path "$arg")";; esac
  if [ -z "$so" ] || [ ! -f "$so" ]; then echo "[atheris] 无法定位 '$arg' 对应的 .so" >&2; exit 2; fi
  if so_is_instrumented "$so"; then echo "INSTRUMENTED: $so"; exit 0
  else echo "NOT-INSTRUMENTED: $so (请用 scripts/build_sanitized.sh 重新构建)" >&2; exit 1; fi
fi

HARNESS="${1:?usage: run_atheris.sh <harness.py> [--time N] [--corpus DIR]}"; shift
TIME=120; CORPUS=""; REQUIRE_INSTR=""; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --time) TIME="$2"; shift 2;;
    --corpus) CORPUS="$2"; shift 2;;
    --require-instrumented) REQUIRE_INSTR="$2"; shift 2;;
    --) shift; EXTRA=("$@"); break;;
    *) EXTRA+=("$1"); shift;;
  esac
done
FIND="${FINDINGS_DIR:-$(dirname "$HARNESS")}"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase dast --actor run_atheris.sh "$@" >/dev/null 2>&1 || true; }

command -v python3 >/dev/null 2>&1 || { echo "[atheris] 缺少 python3" >&2; exit 1; }
python3 -c 'import atheris' 2>/dev/null || { echo "[atheris] 未安装 atheris (pip install atheris)" >&2; exit 1; }

# 定位用于 LD_PRELOAD 的 clang ASAN 运行时。
ASAN_RT=""
if command -v clang >/dev/null 2>&1; then
  ASAN_RT="$(clang -print-file-name=libclang_rt.asan-x86_64.so 2>/dev/null || true)"
fi
[ -f "$ASAN_RT" ] || ASAN_RT="$(ls /usr/lib*/clang/*/lib/linux/libclang_rt.asan-x86_64.so 2>/dev/null | head -1 || true)"

# 拒绝在一个未插桩的目标上声称已具备原生内存安全覆盖率。
NATIVE_COVERAGE="none"
if [ -n "$REQUIRE_INSTR" ]; then
  so="$REQUIRE_INSTR"; case "$REQUIRE_INSTR" in *.so) :;; *) so="$(module_so_path "$REQUIRE_INSTR")";; esac
  if so_is_instrumented "$so"; then
    NATIVE_COVERAGE="asan-instrumented"; echo "[atheris] 原生覆盖率 OK: $so 已 ASAN 插桩" >&2
  else
    echo "[atheris] FATAL: --require-instrumented '$REQUIRE_INSTR' 解析为 '$so'，但其未经 ASAN 插桩。" >&2
    echo "[atheris] 仅靠 LD_PRELOAD 无法捕获其中的内存错误。请通过 scripts/build_sanitized.sh 重新构建。" >&2
    led --kind decision --summary "aborted: target not ASAN-instrumented (no real native coverage)"
    exit 3
  fi
else
  echo "[atheris] WARN: 未提供 --require-instrumented。对于一个已编译完成的 .so，" >&2
  echo "[atheris] LD_PRELOAD 什么都捕获不到。请将其用于纯 Python 或已加 sanitizer 构建目标的" >&2
  echo "[atheris] 崩溃/契约 oracle；对于原生内存错误请传入 --require-instrumented。" >&2
fi

export ASAN_OPTIONS="abort_on_error=1:handle_abort=1:detect_leaks=0:halt_on_error=1:symbolize=1:detect_odr_violation=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer 2>/dev/null || true)"

ART="$(dirname "$HARNESS")/artifacts"; mkdir -p "$ART"
LOG="$ART/atheris_$(date +%s).log"
ARGS=(-runs=2000000 -max_total_time="$TIME" -artifact_prefix="$ART/" "$ART/crash-")
[ -n "$CORPUS" ] && ARGS+=("$CORPUS")
[ ${#EXTRA[@]} -gt 0 ] && ARGS+=("${EXTRA[@]}")

echo "[atheris] preload=${ASAN_RT:-none} native_coverage=$NATIVE_COVERAGE time=${TIME}s" >&2
led --kind tool_call --summary "atheris run start: $(basename "$HARNESS") native_coverage=$NATIVE_COVERAGE"
set +e
if [ -n "$ASAN_RT" ]; then
  LD_PRELOAD="$ASAN_RT" python3 "$HARNESS" "${ARGS[@]}" 2>&1 | tee "$LOG"
else
  python3 "$HARNESS" "${ARGS[@]}" 2>&1 | tee "$LOG"
fi
rc=${PIPESTATUS[0]}
set -e
echo "[atheris] exit=$rc log=$LOG" >&2
led --kind artifact --summary "atheris run log (exit $rc)" --blob "$LOG"
# 将导致崩溃的输入交给 triage。
for c in "$ART"/crash-*; do
  [ -f "$c" ] || continue
  echo "[atheris] 崩溃输入: $c" >&2
done
exit 0
