#!/usr/bin/env bash
# sca_scan.sh — 对 ./code 执行软件成分分析（SCA）。
#
# 黑盒说明：SCA 检查的是依赖项（第三方组件+版本），绝不涉及宿主项目自身的身份信息。
# 它只读取依赖清单以及依赖项自身内嵌的版本标记。它绝不读取目标的
# VERSION/CHANGELOG/RELEASE/SECURITY，也绝不会把项目名称喂给任何“按项目查已知 CVE”的查询。
# OSV/NVD 匹配通过 purl 以 (component, version) 为键进行——这是标准的自动化 SCA，不会泄露目标身份。
#
# 构建 SBOM（syft）并将依赖版本与 OSV/GHSA/NVD 进行匹配
# （osv-scanner、grype、pip-audit、trivy）。每个工具都是可选的且不会致命中断。
# 设置 OFFLINE=1 可使用预先填充的 ./.sca/db OSV 数据库。
#
# 用法: sca_scan.sh <code_dir> <out_dir> [findings_dir]
set -euo pipefail

CODE="${1:?usage: sca_scan.sh <code_dir> <out_dir> [findings_dir]}"
OUT="${2:?usage: sca_scan.sh <code_dir> <out_dir> [findings_dir]}"
FIND="${3:-$(dirname "$OUT")}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/sbom" "$OUT/raw"
export PATH="$PWD/.sca/bin:$PATH"

led(){ [ -x "$HERE/ledger.sh" ] && "$HERE/ledger.sh" append "$FIND" --phase sca --actor sca_scan.sh "$@" >/dev/null 2>&1 || true; }
have(){ command -v "$1" >/dev/null 2>&1; }
run(){ echo "+ $*" >&2; "$@"; }

OFFLINE="${OFFLINE:-0}"
echo "[sca] code=$CODE out=$OUT offline=$OFFLINE" >&2

# ---- SBOM ----
if have syft; then
  run syft scan "dir:$CODE" -o "cyclonedx-json=$OUT/sbom/sbom.cyclonedx.json" \
      -o "spdx-json=$OUT/sbom/sbom.spdx.json" 2>"$OUT/raw/syft.log" || echo "[sca] syft 执行失败" >&2
  led --kind tool_call --summary "syft SBOM" --blob "$OUT/sbom/sbom.cyclonedx.json"
else echo "[sca] 未找到 syft（请运行 sca_install.sh）" >&2; fi

if have trivy; then
  run trivy fs --format cyclonedx --output "$OUT/sbom/sbom.trivy.cyclonedx.json" "$CODE" \
      2>"$OUT/raw/trivy_sbom.log" || true
fi

# 若存在 cyclonedx-py 则生成 Python 专属的 SBOM
for req in "$CODE"/requirements*.txt "$CODE"/*/requirements*.txt; do
  [ -f "$req" ] || continue
  if python3 -m cyclonedx_py --help >/dev/null 2>&1; then
    python3 -m cyclonedx_py requirements "$req" -o "$OUT/sbom/py.$(basename "$req").cdx.json" 2>/dev/null || true
  fi
done

# ---- 漏洞匹配 ----
# OFFLINE=1 仅使用 --offline 针对预先填充的数据库（由 sca_install.sh 在线预热一次）。
# 切勿将 --offline 与 --download-offline-databases 同时使用（两者矛盾）。osv-scanner 的标志/
# 子命令名称在不同版本间会变化，因此先探测 --help 并选择一个存在的形式。
if have osv-scanner; then
  OSV_VER="$(osv-scanner --version 2>&1 | head -1 || echo unknown)"
  HELP="$(osv-scanner scan --help 2>&1 || osv-scanner --help 2>&1 || true)"
  OSV_ARGS=(scan); printf '%s' "$HELP" | grep -q -- '--recursive' && OSV_ARGS+=(--recursive) || OSV_ARGS+=(-r)
  if [ "$OFFLINE" = 1 ]; then
    if printf '%s' "$HELP" | grep -q -- '--offline'; then OSV_ARGS+=(--offline)
    else echo "[sca] 此 osv-scanner 不支持 --offline；改为在线运行" >&2; fi
  fi
  OSV_ARGS+=(--format=json)
  echo "[sca] osv-scanner=$OSV_VER args=${OSV_ARGS[*]} offline=$OFFLINE" >&2
  if ! run osv-scanner "${OSV_ARGS[@]}" "$CODE" >"$OUT/raw/osv.json" 2>"$OUT/raw/osv.log"; then
    # 针对较旧/较新的二进制文件，回退到裸标志形式
    run osv-scanner --format=json -r "$CODE" >"$OUT/raw/osv.json" 2>>"$OUT/raw/osv.log" || true
  fi
  if [ -f "$OUT/sbom/sbom.cyclonedx.json" ]; then
    run osv-scanner scan --format=json --sbom="$OUT/sbom/sbom.cyclonedx.json" \
        >"$OUT/raw/osv_sbom.json" 2>>"$OUT/raw/osv.log" || true
  fi
  led --kind tool_call --summary "osv-scanner ($OSV_VER) args=${OSV_ARGS[*]}" --blob "$OUT/raw/osv.json"
else echo "[sca] 未找到 osv-scanner" >&2; fi

if have grype && [ -f "$OUT/sbom/sbom.cyclonedx.json" ]; then
  run grype "sbom:$OUT/sbom/sbom.cyclonedx.json" -o json >"$OUT/raw/grype.json" 2>"$OUT/raw/grype.log" || true
  led --kind tool_call --summary "grype" --blob "$OUT/raw/grype.json"
fi

if have trivy; then
  run trivy fs --scanners vuln --format json --output "$OUT/raw/trivy.json" "$CODE" 2>>"$OUT/raw/trivy_sbom.log" || true
fi

for req in "$CODE"/requirements*.txt "$CODE"/*/requirements*.txt; do
  [ -f "$req" ] || continue
  if have pip-audit; then
    run pip-audit -r "$req" --format json >"$OUT/raw/pip-audit.$(basename "$req").json" 2>/dev/null || true
  fi
done

# ---- 内嵌（vendored）C/C++ 指纹识别（无清单） ----
if [ -x "$HERE/sca_fingerprint.sh" ]; then
  "$HERE/sca_fingerprint.sh" "$CODE" >"$OUT/raw/vendored.json" 2>/dev/null || echo '[]' >"$OUT/raw/vendored.json"
else
  echo '[]' >"$OUT/raw/vendored.json"
fi

# ---- 归一化 ----
if [ -f "$HERE/sca_normalize.py" ]; then
  python3 "$HERE/sca_normalize.py" "$OUT/raw" "$OUT/raw/vendored.json" >"$OUT/findings.json" \
    || echo '{"schema_version":"sca-1.0","findings":[],"vendored_unidentified":[]}' >"$OUT/findings.json"
else
  echo '{"schema_version":"sca-1.0","findings":[],"vendored_unidentified":[]}' >"$OUT/findings.json"
fi
led --kind artifact --summary "sca findings normalized" --blob "$OUT/findings.json"
echo "[sca] 完成 -> $OUT/findings.json" >&2
