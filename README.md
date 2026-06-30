# 基于 AI 的漏洞挖掘 — AI-Based Vulnerability Mining

一套工程级、**黑盒**、**证据驱动**的漏洞发现系统，封装为一个可复用的 [Claude Code 技能](.claude/skills/ai-vuln-hunt/SKILL.md)。你只需将任意代码库放入 `code/` 目录并指向它，它便会运行完整的流水线 —— **SCA + SAST 工具链 + 深度 LLM 语义分析 + DAST/模糊测试** —— 其中**每一个上报的缺陷都由 AI 生成的、可运行的 PoC 加以证明**，且**整个 AI 交互过程都被记录在可防篡改、可复现的审计轨迹中**。

本仓库的交付物即技能本身：一套以可执行操作手册形式编码的方法论，外加强制执行该方法论的脚本与模板。

---

## 它如何满足竞赛要求

| # | 要求 | 该技能如何满足 |
|---|-------------|------------------------|
| 1 | **对整个 AI 交互进行完整、可复现率 ≥90% 的记录** | 一条哈希链式、只追加的账本（`ledger.jsonl`）记录每一个步骤；每一条提示词/响应/工具输出都以 SHA-256 内容寻址存放于 `blobs/` 下；`env_manifest.json` 固定工具/模型版本以及一个仅含源码的 `target_tree_sha256`。`ledger.sh verify` 会重新计算哈希链并检测任何 1 字节的改动。确定性以**诚实**的方式呈现：工具可精确重放；LLM 步骤被完整记录（而非声称逐比特可复现）；发现项受 PoC 门控约束，因此一个已确认的缺陷无论在哪次运行中都能通过其 PoC 复现。 |
| 2 | **严格黑盒：绝不被告知项目、版本或已知缺陷** | `blackbox_guard.sh` 是一道硬性闸门：它默认拒绝 `.git/` 以及宿主身份标识文件（`VERSION`、`CHANGELOG`、`RELEASE` 等），仅放行 `git diff/status/ls-files`，并**拦截**任何断言宿主身份/版本（英文**与**中文）或将某个 CVE 与宿主代码挂钩的文本 —— 以非零状态退出从而中止本次运行。针对第三方*依赖*的 SCA 仍被允许（它检查的是组件身份，绝不涉及宿主）。身份**仅以内容哈希**判定。 |
| 3 | **证明每个缺陷为真；任何测试必须由 AI 生成** | "无 PoC，则无缺陷。"`confirm_finding.sh` 是一道**强制执行**的闸门：它依据 JSON 模式校验每一个发现项，**对每一条证据日志独立地重新运行 triage**，并要求 ≥3 次复现出相同的机器判定信号（ASAN/UBSAN/MSAN/信号/abort/CHECK，或某个声明的不变量/差分/蜕变违例），并自动将任何未被证明的项**降级**到 `unconfirmed/`。所有 PoC/测试均由 AI 生成。 |
| 4 | **最大化发挥 LLM；结合传统 + 新颖方法（加分项）** | 将传统的 SCA/SAST/DAST 与 **LLM 语义 SAST**（多跳污点分析 + 缺失检查推理）、一个**多审计员交叉验证小组**（内存安全 / 整数溢出 / 反序列化 / 并发 / 红队）以及**新颖的 ML 视角**相融合：对数值内核进行不变量 / 差分 / 蜕变性质测试，从而发现单靠模糊测试会遗漏的契约缺陷。 |

---

## 流水线

```
Recon ─▶ SCA ─▶ SAST (tools) ─▶ LLM semantic SAST ─▶ Triage ─▶ Cross-validation ─▶ DAST/PoC ─▶ Score ─▶ Report
 auto-detect    SBOM + OSV/    bandit/semgrep/      sink taxonomy   fuse + dedup   5-lens panel   PROVE with    CVSS-   confirmed-
 + rank the     NVD/GHSA       cppcheck/clang-tidy  + reviewer      candidates     (prunes noise) AI PoC +      style   only,
 attack surface (deps only)    + flawfinder         protocol                                      oracle gate           reproducible
```

- **规模感知**：它从不读取整棵代码树 —— 而是对攻击面进行排序并采样；工具受时间盒约束、可选，且不致命。
- **各阶段之间设有闸门**：没有可达入口点的候选项，或没有可复现 PoC 的发现项，绝不会向前推进。交叉验证小组只做*剪枝*；**PoC 是判定"已确认"的唯一仲裁者**。

## 使用方法

```bash
# 1) Put the target under code/ (the skill treats it as an unknown black box).
# 2) Invoke the skill in Claude Code:
/ai-vuln-hunt
# 3) Outputs land in findings/: ledger.jsonl, env_manifest.json, sbom/, raw/, candidates/,
#    findings/VH-NNNN/ (proof packages), unconfirmed/, and REPORT.md.
```

Claude 所遵循的操作手册是 [`.claude/skills/ai-vuln-hunt/SKILL.md`](.claude/skills/ai-vuln-hunt/SKILL.md)。

## 机制有效性的证明

```bash
bash .claude/skills/ai-vuln-hunt/scripts/selftest.sh     # => "13 pass, 0 fail"
```

自测会构建一个真实的越界写目标，生成一个 PoC，触发一次真实的 ASAN 崩溃，对其进行 triage，搭建出一个发现项，并运行证明闸门直至 CONFIRMED —— 随后证明一个**伪造的** CONFIRMED 发现项会被自动降级。一次已捕获、自洽的运行记录位于 [`.claude/skills/ai-vuln-hunt/examples/oob_demo/`](.claude/skills/ai-vuln-hunt/examples/oob_demo/)（其 `finding.json` 在干净检出上能够通过 `confirm_finding.sh`）。

## 目录结构

```
.claude/skills/ai-vuln-hunt/
  SKILL.md                  # the end-to-end runbook (the methodology)
  scripts/                  # ledger, blackbox_guard, SCA/SAST/DAST tooling, confirm_finding, selftest
  templates/                # reviewer prompt, sink taxonomy, harnesses, JSON schemas, report
  examples/oob_demo/        # a captured, gate-passing worked example
code/                       # (you add) the target codebase — treated as a black box
findings/                   # (generated) the reproducible audit trail + proof packages + REPORT.md
```
