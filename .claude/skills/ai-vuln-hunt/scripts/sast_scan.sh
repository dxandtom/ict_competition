#!/usr/bin/env bash
# sast_scan.sh — 在 ./code 上运行现成的静态分析器，并对结果归一化 + 排序。
#
# 黑盒说明：仅作用于 code/ 下的源码。绝不读取/传递身份文件
# （VERSION/CHANGELOG/RELEASE/SECURITY）。--changed-from 仅用 `git diff RANGE` 来
# 限定范围，绝不使用 tag/log 作为身份信息。依赖版本 SCA 是独立的阶段。
#
# 每个工具都是可选的、带时间限制的且非致命的。将每个工具的原始输出写入
# <out>/raw，并将归一化、去重、排序后的线索文件写入 <out>/leads.json。
#
# 用法: sast_scan.sh <code_dir> <out_dir> [findings_dir] [--changed-from REF] [--subtree DIR]
set -euo pipefail
CODE="${1:?usage: sast_scan.sh <code_dir> <out_dir> [findings_dir]}"; shift
OUT="${1:?out_dir}"; shift
FIND="${1:-$(dirname "$OUT")}"; [ $# -gt 0 ] && shift || true
CHANGED=""; SUBTREE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --changed-from) CHANGED="$2"; shift 2;;
    --subtree) SUBTREE="$2"; shift 2;;
    *) shift;;
  esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/raw"
SCOPE="${SUBTREE:-$CODE}"
TIMEBOX="${TIMEBOX:-600}"
EXCLUDE='--exclude=*/third_party/* --exclude=*/external/* --exclude=*/test/* --exclude=*/tests/* --exclude=*/vendor/*'

led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase sast --actor sast_scan.sh "$@" >/dev/null 2>&1 || true; }
have(){ command -v "$1" >/dev/null 2>&1; }
tb(){ timeout "$TIMEBOX" "$@" || echo "[sast] 超时/失败: $*" >&2; }

# 解析变更文件范围（仅用 git diff——绝不用 tag/log）
if [ -n "$CHANGED" ]; then
  if [ -x "$HERE/blackbox_guard.sh" ]; then "$HERE/blackbox_guard.sh" check-git diff "$CHANGED" >/dev/null; fi
  git -C "$CODE" diff --name-only "$CHANGED" 2>/dev/null | sed "s#^#$CODE/#" >"$OUT/raw/changed_files.txt" || true
fi

echo "[sast] scope=$SCOPE changed=${CHANGED:-none}" >&2

# ---------- Python ----------
if have bandit; then
  tb bandit -r "$SCOPE" -f json -ll -ii -o "$OUT/raw/bandit.json" 2>/dev/null || true
  led --kind tool_call --summary "bandit" --blob "$OUT/raw/bandit.json"
fi
if have ruff; then
  tb ruff check "$SCOPE" --select S,B,E9,F --output-format json >"$OUT/raw/ruff.json" 2>/dev/null || true
fi
if have semgrep; then
  tb semgrep scan --config p/python --config p/security-audit --sarif \
     --output "$OUT/raw/semgrep_py.sarif" $EXCLUDE "$SCOPE" 2>/dev/null || true
  led --kind tool_call --summary "semgrep python" --blob "$OUT/raw/semgrep_py.sarif"
fi

# ---------- C/C++ ----------
if have flawfinder; then
  tb flawfinder --sarif --minlevel=2 "$SCOPE" >"$OUT/raw/flawfinder.sarif" 2>/dev/null || true
fi
if have cppcheck; then
  tb cppcheck --enable=warning,style,performance,portability --inconclusive --xml \
     "$SCOPE" 2>"$OUT/raw/cppcheck.xml" || true
  led --kind tool_call --summary "cppcheck" --blob "$OUT/raw/cppcheck.xml"
fi
if have clang-tidy; then
  # clang-tidy/clang-analyzer 需要一个编译数据库。尝试获取一个；如果获取不到则记录日志。
  CDB=""
  if [ -f "$CODE/compile_commands.json" ]; then CDB="$CODE"
  elif have bear; then
    echo "[sast] 通过 bear 生成 compile_commands.json 依赖具体构建方式；跳过自动生成" >&2
  fi
  if [ -n "$CDB" ]; then
    # 若存在 recon 排序后的热点文件则优先使用，否则使用全部 C/C++ 编译单元（分组谓词）。
    CAP="${CLANG_TIDY_CAP:-400}"
    if [ -f "$FIND/recon_hot.txt" ]; then
      LIST="$(grep -E '\.(c|cc|cpp|cxx|cu|C)$' "$FIND/recon_hot.txt" 2>/dev/null | head -"$CAP")"
    else
      LIST="$(find "$SCOPE" \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \
               -o -name '*.cu' -o -name '*.C' \) -print 2>/dev/null | head -"$CAP")"
    fi
    N="$(printf '%s\n' "$LIST" | grep -c . || true)"
    echo "[sast] 对 $N 个文件运行 clang-tidy（上限 $CAP）" >&2
    printf '%s\n' "$LIST" | while read -r src; do
      [ -n "$src" ] || continue
      tb clang-tidy --checks='clang-analyzer-*,bugprone-*,cert-*' -p "$CDB" "$src" \
        >>"$OUT/raw/clang-tidy.txt" 2>/dev/null || true
    done
    led --kind tool_call --summary "clang-tidy ($N files, cap $CAP)"
  else
    echo "[sast] clang-tidy 已跳过: 无 compile_commands.json（未运行深度 clang-analyzer 污点分析）；" \
         "生成一个（bazel aquery+compdb 或 bear）以启用。LLM 语义分析阶段会弥补此缺口。" \
      | tee -a "$OUT/raw/clang-tidy.skipped.txt" >&2
    led --kind note --summary "clang-tidy skipped: no compile_commands.json"
  fi
fi
if have semgrep; then
  tb semgrep scan --config p/c --config p/cpp --sarif \
     --output "$OUT/raw/semgrep_c.sarif" $EXCLUDE "$SCOPE" 2>/dev/null || true
fi

# 可选的 CodeQL（较重，需要构建），由 CODEQL=1 控制
if [ "${CODEQL:-0}" = 1 ] && have codeql; then
  echo "[sast] CodeQL 已启用（较重）——先构建数据库，然后用 security-extended 进行分析" >&2
fi

# ---------- 归一化 + 排序 ----------
if [ -f "$HERE/sast_merge.py" ]; then
  python3 "$HERE/sast_merge.py" "$OUT/raw" >"$OUT/leads.json" \
    || echo '{"schema":"sast-leads-1.0","leads":[]}' >"$OUT/leads.json"
else
  echo '{"schema":"sast-leads-1.0","leads":[]}' >"$OUT/leads.json"
fi
led --kind artifact --summary "sast leads ranked" --blob "$OUT/leads.json"
echo "[sast] done -> $OUT/leads.json" >&2
