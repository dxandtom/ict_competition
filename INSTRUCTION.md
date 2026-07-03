# INSTRUCTION.md — 裁判执行说明书

> 赛题：**基于 AI 的漏洞挖掘**。本题考点是**如何发现 bug**（而非修复），因此本作品的“结果”
> 即发现的**漏洞清单 / 大模型交互记录 / 工程化报告**三份交付物，以及证明其真实性的证据包。
> 作品形式为 **Claude Code Skill + 配套脚本**（一套工程化黑盒漏洞挖掘体系）。

自动评测系统按本说明书即可**全自动、无人工交互**地完成：环境准备 → 执行 → 判定完成 → 获取结果。

---

## 0. 目录结构（提交内容）

```
INSTRUCTION.md                     # 本说明书（裁判执行说明）
work/
├── vulnerability_list.md          # 【必交】漏洞清单（按赛题模板）
├── llm_chat_log.json              # 【必交】完整、黑盒、可复现的大模型交互记录
├── vulnerability_report.md        # 【必交】漏洞审查工程化报告
├── setup_env.sh                   # 环境准备（非交互）
├── verify.sh                      # 执行入口（确定性、自包含校验；主评测路径）
├── run_pipeline.sh                # （可选）端到端完整复现
├── STATUS.txt                     # 执行完成标记（由 verify.sh 生成）
├── evidence/                      # 证据与可复现材料
│   ├── findings/VH-0001/, VH-0002/#   每条漏洞：poc.py + run.sh + oracle.json + 3份证据日志 + finding.json
│   ├── ledger.jsonl               #   哈希链审计轨迹（可 verify）
│   ├── env_manifest.json          #   环境/工具/模型/目标源码内容哈希
│   └── dast/                      #   黑盒崩溃扫描器（raw_fuzz.py）
└── skills/ai-vuln-hunt/           # 方法体系本体（Skill：SKILL.md + scripts + templates）
                                   #   （符合 work/skills/{name}/SKILL.md 规范）
```

> 平台提供的目标材料（如 `/app/code/judge-assets/01_02_vulnerability_detection`）**无需**由本作品提交；
> 本作品未修改任何 REST API 契约。

---

## 4.1 环境准备

**主评测路径（`verify.sh`）仅依赖：** `bash`、GNU coreutils（`sha256sum` 等）、`jq`、`python3`。
一条命令即可自动完成（非交互，自动适配 apt/dnf/yum/apk/brew/conda）：

```bash
bash work/setup_env.sh
```

若环境已具备 `jq` 与 `python3`，可跳过本步。**无需联网、无需构建、无需目标源码。**

> 完整复现路径（`run_pipeline.sh`，可选）另需：`python3.10` + `uv` + 目标运行时。
> 目标运行时通过环境变量提供：`AIVH_PY=<装好目标发行包的python>`，或 `TARGET_DIST=<目标pip包>`
> 由脚本用 `uv` 自动建 venv 安装；目标源码通过 `TARGET_SRC=<源码目录>` 提供（缺省自动探测
> `/app/code/judge-assets/*/` 或 `./code`）。这些均可自动完成，无人工交互。

## 4.2 执行方式

**主执行命令（推荐，确定性且自包含）：**

```bash
bash work/verify.sh
```

它会：核对三份必交交付物存在且非空 → 校验 `llm_chat_log.json` 为合法 JSON 且结构正确 →
对三份交付物做**黑盒合规扫描**（无身份/版本/CVE 断言）→ 对每条漏洞**重新运行分类研判、要求
≥3 份证据日志复现所记录的 oracle**（证据自洽，独立于目标源码）→ 校验**哈希链账本完整** →
（若提供了目标源码则额外做含 `code/` 崩溃帧的完整门禁复核）→ 写出 `work/STATUS.txt` 并退出。

**（可选）端到端完整复现**（对目标运行时真跑一遍黑盒崩溃扫描并重新生成交付物）：

```bash
# 例：AIVH_PY 指向已装目标发行包的 python；TARGET_SRC 指向目标源码目录
AIVH_PY=/path/to/target/python TARGET_SRC=/app/code/judge-assets/01_02_vulnerability_detection/<src> \
  bash work/run_pipeline.sh
# 或：TARGET_DIST=<目标pip包> bash work/run_pipeline.sh   # 由脚本自动建 venv
```

`run_pipeline.sh` 在缺少目标运行时/源码时会**自动退化**为 `verify.sh`，不会中断、不需人工介入。

**执行顺序：** `setup_env.sh`（一次）→ `verify.sh`（或 `run_pipeline.sh`）。二者均非交互。

## 4.3 执行完成判定

以下任一即表示执行完成且成功：

- **命令退出码为 `0`**（`bash work/verify.sh; echo $?` 输出 `0`）；且
- 生成完成标记文件 **`work/STATUS.txt`**，其内容首行为 **`STATUS=DONE`**；且
- 终端末尾打印 `== 结果：N 通过 / 0 失败 ==`。

失败时退出码为非 `0`，`work/STATUS.txt` 首行为 `STATUS=FAILED`，并在终端以 `[FAIL]` 标出具体项。

## 4.4 结果获取方式

评测系统从以下**固定路径**获取最终结果（本题为漏洞发现题，“结果”即下列交付物）：

| 交付物 | 路径 |
|---|---|
| 漏洞清单 | `work/vulnerability_list.md` |
| 大模型交互记录 | `work/llm_chat_log.json` |
| 工程化报告 | `work/vulnerability_report.md` |
| 完成状态 | `work/STATUS.txt` |
| 每条漏洞的证明包（PoC + 证据日志 + oracle + finding.json） | `work/evidence/findings/VH-*/` |
| 哈希链审计轨迹 | `work/evidence/ledger.jsonl` |
| 环境/工具/模型清单 | `work/evidence/env_manifest.json` |

若运行了 `run_pipeline.sh`，重新生成的交付物同样落在上述 `work/` 路径（原地覆盖）。

---

## 5. 与赛题要求的对应

- **完整、可复现（≥90%）的 AI 交互记录，无删改** → `work/llm_chat_log.json`（黑盒多轮对话）
  + `work/evidence/ledger.jsonl`（哈希链，`ledger.sh verify` 可证明未被篡改）。
- **黑盒、不告知目标身份/版本/已知缺陷** → `skills/ai-vuln-hunt/scripts/blackbox_guard.sh` 强制；
  身份文件仅按路径记录、内容未读（见 `env_manifest.json:identity_files_seen_but_unread`）；
  三份交付物均通过黑盒扫描（`verify.sh` 第 3 步会复核）。
- **证明发现的 Bug 真实、测试由 AI 生成** → 每条漏洞含 AI 生成 `poc.py` + 3 次确定性复现 +
  强制证据门禁 `confirm_finding.sh`（`verify.sh` 第 4 步会复核）。
- **工程化体系 + 传统方法 + 创新（加分）** → SCA + SAST 工具 + LLM 语义分析 + DAST（隔离子进程
  崩溃后续跑的黑盒模糊测试）+ 强制证据门禁 + glog/CHECK-fail 识别，详见 `vulnerability_report.md`
  与 `skills/ai-vuln-hunt/SKILL.md`。

## 6. 合规性自检（对照“注意事项”）

- ✅ 含 `INSTRUCTION.md`，可指导全自动执行；执行过程**无人工交互**。
- ✅ 完成可判定（退出码 0 + `work/STATUS.txt=DONE`）。
- ✅ 结果路径固定、可获取。
- ✅ 未修改任何 REST API 契约。
- ✅ 提供了方案说明（`vulnerability_report.md`）与验证方案（`verify.sh` / `run_pipeline.sh`）。
- ✅ Skill 位于 `work/skills/ai-vuln-hunt/SKILL.md`，符合路径规范。
