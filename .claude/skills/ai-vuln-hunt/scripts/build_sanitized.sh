#!/usr/bin/env bash
# build_sanitized.sh — 生成目标（或某个关键单元）的 ASAN/UBSAN 插桩构建，
# 因为 LD_PRELOAD 不会对已经编译好的 .so 进行插桩。两种模式：
#
#   build_sanitized.sh bazel <bazel_target> [-- extra bazel args]
#       通过一个临时的 --config，以 -fsanitize=address,undefined 构建 //<target>。
#       当目标由 Bazel 构建、且你想要经过插桩的真实原生扩展时使用。慢但
#       忠实（无桩代码）——是原生内存安全 PoC 的黄金标准。
#
#   build_sanitized.sh so <out.so> <unit1.cc> [unit2.cc ...] [-- -Icode/include ...]
#       将指定的翻译单元编译为经过插桩的共享对象（-shared -fPIC）。
#       忠实于这些单元的真实代码；仅在可疑逻辑自包含时使用。
#
# 构建完成后，用以下命令验证：  scripts/run_atheris.sh check-instrumented <out.so>
#
# 黑盒说明：在 code/ 下构建源码；不触碰任何身份标识文件。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:?usage: build_sanitized.sh {bazel <target>|so <out.so> <unit.cc>...} [-- args]}"; shift
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "${FINDINGS_DIR:-.}" --phase dast --actor build_sanitized.sh "$@" >/dev/null 2>&1 || true; }

case "$MODE" in
  bazel)
    TARGET="${1:?bazel target}"; shift || true
    EXTRA=(); seen=0; for a in "$@"; do [ "$a" = "--" ] && { seen=1; continue; }; [ "$seen" = 1 ] && EXTRA+=("$a"); done
    command -v bazel >/dev/null 2>&1 || command -v bazelisk >/dev/null 2>&1 || { echo "[san] 未安装 bazel" >&2; exit 1; }
    BZ="$(command -v bazel || command -v bazelisk)"
    echo "[san] 以 ASAN/UBSAN 执行 bazel build $TARGET（这可能耗时很久）" >&2
    led --kind tool_call --summary "bazel asan build: $TARGET"
    "$BZ" build "$TARGET" \
      --copt=-fsanitize=address --copt=-fsanitize=undefined --copt=-fno-omit-frame-pointer \
      --copt=-g --linkopt=-fsanitize=address --linkopt=-fsanitize=undefined \
      --strip=never --compilation_mode=dbg "${EXTRA[@]}" \
      || { echo "[san] bazel asan 构建失败（见上方输出）。请尝试更小的目标或 'so' 模式。" >&2; exit 1; }
    echo "[san] 已构建。产物位于 bazel-bin/ 下。将 PYTHONPATH 指向插桩后的扩展，" >&2
    echo "[san] 然后执行：run_atheris.sh check-instrumented <module-or-.so>" >&2
    ;;
  so)
    OUT="${1:?out.so}"; shift
    UNITS=(); EXTRA=(); seen=0
    for a in "$@"; do if [ "$a" = "--" ]; then seen=1; continue; fi
      if [ "$seen" = 1 ]; then EXTRA+=("$a"); else UNITS+=("$a"); fi; done
    [ "${#UNITS[@]}" -ge 1 ] || { echo "[san] 至少需要一个 unit.cc" >&2; exit 2; }
    CXX="${CXX:-clang++}"; command -v "$CXX" >/dev/null 2>&1 || CXX=g++
    command -v "$CXX" >/dev/null 2>&1 || { echo "[san] 没有 C++ 编译器" >&2; exit 1; }
    mkdir -p "$(dirname "$OUT")"
    echo "[san] $CXX $SAN -shared -fPIC ${UNITS[*]} -> $OUT" >&2
    led --kind tool_call --summary "sanitized .so build: $(basename "$OUT")"
    "$CXX" $SAN -shared -fPIC "${EXTRA[@]}" "${UNITS[@]}" -o "$OUT" \
      || { echo "[san] 编译失败；该单元很可能需要更多其真实依赖（-I / .cc）。" >&2; exit 1; }
    if bash "$HERE/run_atheris.sh" check-instrumented "$OUT" >/dev/null 2>&1; then
      echo "[san] OK: $OUT 已完成 ASAN 插桩" >&2
    else
      echo "[san] WARN: 已构建 $OUT，但未找到插桩标记（编译器可能不支持 ASAN）" >&2
    fi
    ;;
  *) echo "usage: build_sanitized.sh {bazel <target>|so <out.so> <unit.cc>...} [-- args]" >&2; exit 2;;
esac
