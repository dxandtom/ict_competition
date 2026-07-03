#!/usr/bin/env bash
# setup_env.sh — 非交互地准备最小运行环境（供校验路径 work/verify.sh 使用）。
# 校验路径只需要：bash、coreutils（sha256sum 等）、jq、python3。
# 完整复现路径（work/run_pipeline.sh）另需 python3.10 + uv + 目标运行时（见 INSTRUCTION.md）。
set -uo pipefail
say(){ echo "[setup_env] $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

install_pkg(){  # $@ = 包名
  if have apt-get; then apt-get update -y >/dev/null 2>&1; apt-get install -y "$@" >/dev/null 2>&1
  elif have dnf; then dnf install -y "$@" >/dev/null 2>&1
  elif have yum; then yum install -y "$@" >/dev/null 2>&1
  elif have apk; then apk add --no-cache "$@" >/dev/null 2>&1
  elif have brew; then brew install "$@" >/dev/null 2>&1
  elif have conda; then conda install -y "$@" >/dev/null 2>&1
  else return 1; fi
}

for tool in jq python3; do
  if have "$tool"; then say "$tool 已就绪：$($tool --version 2>&1 | head -1)"
  else say "安装 $tool …"; install_pkg "$tool" && say "$tool 已安装" || say "无法自动安装 $tool，请手动安装"; fi
done

chmod +x "$(cd "$(dirname "$0")" && pwd)"/*.sh "$(cd "$(dirname "$0")" && pwd)"/skills/ai-vuln-hunt/scripts/*.sh 2>/dev/null || true
if have jq && have python3; then say "环境就绪：可执行 bash work/verify.sh"; exit 0
else say "缺少 jq 或 python3，请先安装后再运行 work/verify.sh"; exit 1; fi
