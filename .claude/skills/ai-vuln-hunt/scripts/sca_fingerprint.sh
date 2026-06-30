#!/usr/bin/env bash
# sca_fingerprint.sh — 为没有清单文件的内嵌 C/C++ 代码进行版本指纹识别。
#
# 黑盒说明：仅遍历 vendor 目录（third_party/external/deps/vendor/contrib）。
# 读取某个依赖自身内嵌的版本标记（其头文件、CMakeLists、AC_INIT）。
# 这些是组件自身的标识，而非宿主目标的标识——符合规范。
#
# 输出一个 JSON 数组，元素为 {path, library_guess, version_guess, method}，置信度为 "low"。
# 用法： sca_fingerprint.sh <code_dir>
set -euo pipefail
CODE="${1:?usage: sca_fingerprint.sh <code_dir>}"
VEND_RE='/(third_party|external|deps|vendor|contrib|3rdparty)/'

emit_first=1
echo "["
while IFS= read -r f; do
  base="$(basename "$f")"
  guess=""; ver=""; method=""
  # 整宏匹配：  #define FOO_VERSION "1.2.3"
  line="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION[[:space:]]+"[0-9]+(\.[0-9]+)+"' "$f" 2>/dev/null | head -1 || true)"
  if [ -n "$line" ]; then
    ver="$(printf '%s' "$line" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)"; method="c_version_macro"
  fi
  # 拆分宏的重组
  if [ -z "$ver" ]; then
    maj="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_MAJOR[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    min="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_MINOR[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    pat="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_PATCH[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    if [ -n "$maj" ] && [ -n "$min" ]; then ver="${maj}.${min}.${pat:-0}"; method="c_version_macro_split"; fi
  fi
  # CMake project(... VERSION x.y.z)
  if [ -z "$ver" ] && [ "$base" = "CMakeLists.txt" ]; then
    ver="$(grep -aioE 'project[[:space:]]*\([^)]*VERSION[[:space:]]+[0-9]+(\.[0-9]+)+' "$f" 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)"
    [ -n "$ver" ] && method="cmake_project_version"
  fi
  # autoconf AC_INIT
  if [ -z "$ver" ]; then
    ver="$(grep -aoE 'AC_INIT\([^,]+,[[:space:]]*\[?[0-9]+(\.[0-9]+)+' "$f" 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)"
    [ -n "$ver" ] && method="autoconf_ac_init"
  fi
  [ -z "$ver" ] && continue
  # 库名猜测 = vendor 子目录名
  guess="$(printf '%s' "$f" | sed -E 's#.*/(third_party|external|deps|vendor|contrib|3rdparty)/([^/]+)/.*#\2#')"
  [ "$emit_first" = 1 ] && emit_first=0 || echo ","
  printf '{"path":"%s","library_guess":"%s","version_guess":"%s","method":"%s"}' \
    "$f" "$guess" "$ver" "$method"
done < <(find "$CODE" -type f \( -name '*.h' -o -name '*.hpp' -o -name 'CMakeLists.txt' -o -name 'configure.ac' \) 2>/dev/null | grep -E "$VEND_RE" || true)
echo
echo "]"
