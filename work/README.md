# work/ — 参赛作品交付目录

本目录为「基于 AI 的漏洞挖掘」参赛作品。作品形式为 **Claude Code Skill + 配套脚本**
（一套工程化的黑盒漏洞挖掘体系），并附一次针对真实大型原生库的实跑成果（两条已证明漏洞）。

## 必交交付物（赛题要求）
- **`vulnerability_list.md`** — 漏洞清单（按赛题模板）。
- **`llm_chat_log.json`** — 完整、黑盒、可复现的大模型交互记录。
- **`vulnerability_report.md`** — 漏洞审查工程化报告。

## 佐证与可复现材料
- `evidence/findings/VH-*/` — 每条漏洞的证明包：AI 生成 `poc.py` + `run.sh` + `oracle.json` + 3 份证据日志 + `finding.json`。
- `evidence/ledger.jsonl` — 哈希链审计轨迹（`ledger.sh verify` 可校验，链完整）。
- `evidence/env_manifest.json` — 环境/工具/模型/目标源码内容哈希。
- `evidence/dast/` — 黑盒崩溃扫描器（`raw_fuzz.py`：隔离子进程 + 崩溃后续跑）。
- `skills/ai-vuln-hunt/` — 方法体系本体（SKILL.md 操作手册 + 脚本 + 模板）。

## 一键校验 / 复现
- `bash work/verify.sh` — **确定性、自包含**校验（无需联网/目标源码）：核对三份交付物、
  黑盒合规、证据复现一致、账本链完整；成功写出 `work/STATUS.txt` 并退出 0。
- `bash work/run_pipeline.sh` — **（可选）完整复现**：对目标运行时做黑盒动态崩溃扫描并重新
  生成三份交付物（需目标源码 `TARGET_SRC` 与运行时 `AIVH_PY`/`TARGET_DIST`，见 INSTRUCTION.md）。

裁判执行说明见仓库根目录 **`INSTRUCTION.md`**。
