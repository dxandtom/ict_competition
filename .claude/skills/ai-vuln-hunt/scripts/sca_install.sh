#!/usr/bin/env bash
# sca_install.sh — 将 SCA 工具安装到 ./.sca/bin（无需 root 权限）。全部为尽力而为。
#
# 每个工具的优先级顺序：已有二进制 -> go install -> release/install.sh -> pip --user。
# 对于离线（air-gapped）运行，请预先填充 ./.sca/db 并向 sca_scan.sh 传入 OFFLINE=1。
set -euo pipefail
BIN="$PWD/.sca/bin"; DB="$PWD/.sca/db"
mkdir -p "$BIN" "$DB"
export PATH="$BIN:$PATH" GOBIN="$BIN"
have(){ command -v "$1" >/dev/null 2>&1; }
echo "[sca-install] target=$BIN" >&2

# osv-scanner
if ! have osv-scanner; then
  go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null \
    || echo "[sca-install] osv-scanner: go install 失败（需要网络/go）" >&2
fi
# syft + grype（官方安装脚本会将文件放入 $BIN）
if ! have syft; then
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] syft: 安装脚本失败" >&2
fi
if ! have grype; then
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] grype: 安装脚本失败" >&2
fi
# trivy
if ! have trivy; then
  curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh 2>/dev/null \
    | sh -s -- -b "$BIN" 2>/dev/null || echo "[sca-install] trivy: 安装脚本失败" >&2
fi
# python 工具
python3 -m pip install --user --quiet pip-audit cyclonedx-bom 2>/dev/null \
  || echo "[sca-install] pip 工具: pip install 失败" >&2

# 预热离线 OSV 数据库 —— 这需要网络（它会下载），因此此处不要传入 --offline。
# 之后的离线扫描仅传入 --offline 来针对这个预先填充的数据库扫描。（缺陷：--offline 与
# --download-offline-databases 在同一次调用中是相互矛盾的。）
if have osv-scanner; then
  echo "[sca-install] 正在预热离线 OSV 数据库（需要网络）…" >&2
  osv-scanner scan --download-offline-databases --recursive . >/dev/null 2>&1 \
    || osv-scanner --download-offline-databases -r . >/dev/null 2>&1 \
    || echo "[sca-install] 离线数据库预热失败（无网络 / 标志漂移）—— 在线扫描仍可工作" >&2
fi
echo "[sca-install] 完成。PATH 前置：export PATH=\"$BIN:\$PATH\"" >&2
