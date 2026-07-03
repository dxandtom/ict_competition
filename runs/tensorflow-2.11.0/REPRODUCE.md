# 真实目标运行记录 — 如何复现

这是 `ai-vuln-hunt` 技能对一个真实大型 Python + C/C++ 目标（放入 `code/`）的一次实跑记录。
**两个已确认漏洞**由 AI 生成的 PoC 证明、每个 3/3 次确定性复现、并通过强制证据门禁。

- 完整报告：[`REPORT.md`](./REPORT.md)
- 证明包：[`VH-0001/`](./VH-0001/)、[`VH-0002/`](./VH-0002/)（各含 `poc.py`、`run.sh`、
  `oracle.json`、3 份 `evidence/run*.log`、`finding.json`）
- 发现过程的原始产物：[`dast/`](./dast/)（`raw_fuzz.py` 崩溃扫描器 + `crashes.jsonl`）
- 可复现审计轨迹：[`ledger.jsonl`](./ledger.jsonl)（哈希链，23 条）、[`env_manifest.json`](./env_manifest.json)

> 说明：`<REPO>` 是运行时仓库根路径的占位符；`run.sh` 用 `${AIVH_PY:-python3}` 指向运行时。
> 目标的身份对**操作者**是已知的，但从未喂给分析过程 —— 审计轨迹保持黑盒（`identity_files_seen_but_unread`
> 仅记录路径、未读内容；无任何“这是 X 项目 Y 版本”的断言）。

## 环境
- Linux，`python3.10`，`clang`/`gcc`，`jq`。
- 目标运行时（用于动态确认）：Python 3.10 venv + 目标发行包（本次为 `tensorflow-cpu==2.11.0`）。

## 复现步骤
```bash
# 1) 取得目标源码到 code/（本次用 tarball，避免受限的 git 代理）：
curl -sSL https://codeload.github.com/<owner>/<repo>/tar.gz/refs/tags/<tag> | tar xz
mv <repo>-<tag> code

# 2) 目标运行时 venv（动态确认所需）：
uv venv --python 3.10 .venv310
uv pip install --python .venv310 "tensorflow-cpu==2.11.0" "numpy<1.24" hypothesis
export AIVH_PY="$PWD/.venv310/bin/python"

# 3) 初始化黑盒账本：
export SKILL="$PWD/.claude/skills/ai-vuln-hunt" FINDINGS="$PWD/findings" CODE_ROOT="$PWD/code"
export AIVH_MODEL="<model-id>"
bash "$SKILL/scripts/ledger.sh" init "$FINDINGS" code

# 4) DAST：隔离子进程 + 崩溃后续跑的崩溃扫描（发现阶段）：
$AIVH_PY dast/raw_fuzz.py gen
$AIVH_PY dast/raw_fuzz.py drive        # -> crashes.jsonl

# 5) 复现某个崩溃 -> triage -> 强制门禁：
$AIVH_PY VH-0001/poc.py                # 进程 abort（CHECK failed），rc=134
CODE_ROOT="$PWD/code" bash "$SKILL/scripts/triage_crash.sh" VH-0001/evidence/run1.log
CODE_ROOT="$PWD/code" bash "$SKILL/scripts/confirm_finding.sh" validate <finding_dir>
```

## 一键复现单个发现
```bash
AIVH_PY=./.venv310/bin/python bash VH-0001/run.sh   # => Check failed: num_threads >= 1 (1 vs. 0); exit=134
AIVH_PY=./.venv310/bin/python bash VH-0002/run.sh   # => Check failed: num_threads >= 1 (1 vs. -2147483647)
```

## 校验证据链与合规
```bash
bash "$SKILL/scripts/ledger.sh" verify <findings_dir>          # 链完整
bash "$SKILL/scripts/blackbox_guard.sh" scan-file REPORT.md    # 无身份断言（路径名仅软警告）
```
