---
name: ai-vuln-hunt
description: 使用本技能对放置于 code/ 目录中的目标代码库执行黑盒、证据驱动的漏洞挖掘，将 SCA + SAST 工具 + DAST/模糊测试与深度 LLM 语义分析相结合，其中每一个上报的缺陷都由 AI 生成的可运行 PoC 加以证明，且整个 AI 交互过程都被捕获到一份可复现、哈希链式的审计轨迹中。
---

# AI-Based Vulnerability Hunting (基于AI的漏洞挖掘)

你正在针对**位于本地 `code/` 目录中的目标代码库**运行一条系统化、工程级的漏洞挖掘流水线。你将传统
技术（SCA、SAST、DAST/模糊测试）与深度 LLM 语义分析相结合，并用一个可运行的、AI 生成的概念验证
（PoC）来**证明（PROVE）**每一个上报的缺陷。

本文件是你端到端的操作手册。请按顺序遵循。它与目标无关：你需要**自动检测**技术栈并随之适配。代码库
可能多达数百万行——你必须**分诊、排序并采样**；你**绝不能**试图把所有内容都读一遍。

在会话开始时一次性建立两个变量：

```bash
SKILL="$(dirname "$(find . -path '*ai-vuln-hunt/SKILL.md' | head -1)")"   # this skill dir
FINDINGS="$(cd code/.. && pwd)/findings"                                  # output root: code/../findings
chmod +x "$SKILL"/scripts/*.sh 2>/dev/null || true
```

所有脚本位于 `$SKILL/scripts/`，所有模板位于 `$SKILL/templates/`。本操作手册**引用**它们；它不会
重复它们的内容。

---

## 0. 三条不可妥协的契约（在做任何事之前阅读）

### 0.1 黑盒契约——你绝不能做的事

操作者**永远不会**告诉你项目是什么、它的版本，或某个特定缺陷是否存在。一切都要**从代码本身**去发现。
因此：

- **不要读取、打开、grep 或传给任何工具/提示词**这些*宿主身份*文件：
  `VERSION`、`version.txt`、`CHANGELOG*`、`RELEASE*`、`NEWS`、`HISTORY*`、`SECURITY.md`、
  `NOTICE`、`AUTHORS`、`CONTRIBUTORS`、仓库内的安全公告，以及 `.git/` 下的任何内容。如果你偶然遇到
  其中之一，把它的路径记录到
  `env_manifest.json:identity_files_seen_but_unread` 中并继续前进。
- **不要**运行 `git tag`、`git log`、`git describe`、`git blame`，或读取 git 历史来推断项目身份/版本。
  `git diff RANGE` **仅**允许用于划定范围。
- **不要**陈述、写出或在提示词中包含任何关于**宿主**目标的、断言"此项目是 X 版本 Y"、"这是一个已知的
  CVE/缺陷"或"此版本对……存在漏洞"的句子。只从你面前的代码进行推理。
- **允许：** 对第三方**依赖**进行 SCA——读取依赖清单
  （`requirements*.txt`、`pyproject.toml`、`WORKSPACE`、`MODULE.bazel`、`third_party/**`）以及
  某个依赖**自身**内嵌的版本标记，并将 `(component, version)` 与 OSV/NVD/GHSA 进行匹配。这检查的是
  *组件*身份，绝不涉及*宿主*身份。

强制是机械式的（`blackbox_guard.sh`），并且它是一道**硬性门禁**，而非尽力而为：

- `check-path <p>` 默认**拒绝（deny）**任何带有 `.git` 组成部分的路径以及任何宿主身份
  基名（`VERSION*`、`CHANGELOG*`、`CHANGES*`、`RELEASE*`、`SECURITY*`、`*.bazel` 版本
  文件，……），同时把依赖清单列入白名单。**在任何你拿不准的 `Read`/`Glob` 目标之前都调用它，并且绝不要
  批量 `Read`。**
- `check-git <args>` 是一份**允许清单**：仅 `diff|status|ls-files` 用于划定范围；`tag`、`log`、
  `describe`、`rev-parse`、`blame`、`show`、…… 都被拒绝。
- `scan-file <f>` / `scan-stdin` 在遇到宿主身份断言（英文或中文）、宿主漏洞声明，或绑定到宿主代码的
  CVE 时**以非零（4）退出**。在记录提示词数据块之前对其扫描时使用 **`--strict`**
  （它会额外拦截来自 `blackbox_denylist.txt` 的任何裸项目名称）；
  对 `REPORT.md` 使用默认模式（为 SCA 放行裸依赖名称，但仍拦截断言）。非零退出意味着**中止并修复**，不要继续。
- 每一条 `ledger.sh` 摘要都会被自动扫描，如果会发生泄露则被遮蔽。

在开始时各运行一次 `bash "$SKILL/scripts/blackbox_guard.sh" selftest` 和 `bash "$SKILL/scripts/selftest.sh"`，
在你信任它们之前，确认守卫与整个证明回路正常工作。

### 0.2 可复现性契约——捕获一切

你必须产出一份**完整、未经篡改、≥90% 可复现**的、关于整个 AI 交互的记录。机制：

- 位于 `$FINDINGS/ledger.jsonl` 的哈希链式仅追加账本。**在每一步都追加一条记录**
  （instruction、tool_call、llm_call、decision、artifact、note），通过
  `bash "$SKILL/scripts/ledger.sh" append "$FINDINGS" --phase P --actor A --kind K --summary S [--blob FILE]...`。
- 大块数据（提示词、工具 argv、模型响应、stdout）以内容寻址方式存放于
  `$FINDINGS/blobs/<sha256>` 之下，并通过哈希引用——绝不内联——这样在数百万行代码的目标上账本仍保持
  小巧。
- LLM 步骤记录确切的 `model` id、`temperature:0`，以及 `input_manifest`
  （所展示的确切代码的 `path::sha256`），外加作为内容寻址数据块的完整提示词**和**响应。每一次分析调用
  都使用 **temperature 0**。
- `env_manifest.json` 固定 OS/内核、每个工具+python+clang 版本、确切的模型 id
  （设置 `AIVH_MODEL`），以及目标的 **`target_tree_sha256`**（一个对*源*文件清单的哈希——绝不包括
  二进制文件/数据集/身份文件；参见 `target_tree_manifest.txt`）。
- `ledger.sh verify "$FINDINGS"` 重新计算链条；1 字节的改动会在确切的记录处使其断裂。**诚实的可复现性
  论证**（参见 `env_manifest.reproducibility_note`）：工具的输入/输出是内容寻址的，可**确定性地**重放；
  LLM 调用*不是*逐位可复现的（没有暴露采样种子）但**已被完整记录且可重新运行**；并且
  由于发现是 **PoC 门控的**，无论是哪一次 LLM 运行浮现了它，一个被确认的缺陷都会通过其 PoC 确定性地
  复现。**不要**声称 LLM 有种子确定性。

### 0.3 证明契约——无 PoC，无缺陷

每一个上报的缺陷都必须由一个**AI 生成的**最小复现器加以证明，且该复现器要触发一个
**机器可检测的判定器**：ASAN/UBSAN/MSAN 报告、SIGSEGV/SIGFPE、abort/CHECK/assert
失败、在不应抛出的代码中出现未捕获异常，或相对一个明确陈述的不变式给出错误结果（差分/蜕变）。如果仓库中
已存在测试，你**不可**依赖它们——任何你作为证明使用的测试都必须是 AI 生成的。**无 PoC ⇒ 状态为
`UNCONFIRMED`，被隔离到 `$FINDINGS/unconfirmed/` 之下，绝不作为缺陷上报。** PoC 是*唯一的*
裁决者；交叉验证评审团只负责修剪噪声，它绝不会提升为已确认。

---

## 1. 预检 + 输出布局（首先做这个）

```bash
# Preflight: prove the machinery (guard + ledger chain + full PoC->confirm loop) works.
bash "$SKILL/scripts/blackbox_guard.sh" selftest
bash "$SKILL/scripts/selftest.sh"                          # expect "N pass, 0 fail"
export AIVH_MODEL="<exact-model-id>"                       # pin the model for the record
bash "$SKILL/scripts/ledger.sh" init "$FINDINGS" code
```

这会创建、而后续运行会填充如下内容：

```
findings/
  env_manifest.json        # env + tool/model versions + seeds + target_tree_sha256
  ledger.jsonl             # hash-chained interaction record (append at EVERY step)
  blobs/<sha256>           # content-addressed prompts/argv/responses/logs
  sbom/                    # CycloneDX + SPDX SBOMs
  raw/                     # untouched per-tool outputs (SCA + SAST + DAST) — the record
    sca/  sast/  dast/
  candidates/              # LLM candidate JSON (candidate.schema.json), xval votes
  findings/VH-NNNN/        # one PROVEN finding each: finding.md, finding.json, poc.*,
                           #   run.sh, evidence/run{1,2,3}.log, oracle.json, score.json
  unconfirmed/             # suspected-but-unproven leads (NOT bugs)
  REPORT.md                # final human report (confirmed-only, ordered by score)
```

在每个阶段边界追加一条 `decision` 账本记录，使该门禁可审计。

---

## 2. Recon 阶段——自动检测技术栈，绘制高风险攻击面（不要读取所有内容）

目标：一份排好序的攻击面地图，而非完整通读。使用 `Glob`/`Grep`，绝不批量 `Read`。

1. **检测技术栈**（作为账本 note 记录）：
   - Python：`Glob code/**/*.py`，是否存在 `requirements*.txt`/`pyproject.toml`/`setup.py`。
   - C/C++：`Glob code/**/*.{c,cc,cpp,h,hpp}`；构建系统通过 `WORKSPACE`/`MODULE.bazel`/
     `BUILD`/`CMakeLists.txt`/`Makefile` 判断。
   - 原生扩展边界（价值最高）：`Grep -n "PyModule_|PYBIND11_|pybind11|Py_BuildValue|nb::module_"`。
2. **定位攻击面**，使用 `templates/sink_taxonomy.md` 中的分类法种子。优先考虑：
   解析器/反序列化器（`pickle`、`ParseFromString`、`tarfile`、`yaml.load`）、张量
   索引/形状运算（`gather`、`scatter`、`reshape`、`stride`、`[idx]`、`data()+`）、大小
   算术（`* sizeof`、维度乘积），以及任何对 64 位维度的 `(int)`/`static_cast<int>` 窄化。
3. **先排序再采样。** 按攻击面密度 × 从公共 API 的可达性给子树打分。仅把排名靠前的单元带入 LLM
   阶段；将排名记录为一条 `decision`，使分诊可复现。绝不要纯粹为了了解身份而 `Read` 某个文件。

在读取任何路径之前先门控：`blackbox_guard.sh check-path <path>`。

---

## 3. SCA 阶段——依赖 CVE 暴露（仅组件身份）

```bash
bash "$SKILL/scripts/sca_install.sh"                       # ./.sca/bin, warms offline OSV DB
bash "$SKILL/scripts/sca_scan.sh" code "$FINDINGS/raw/sca" "$FINDINGS"
# air-gapped: OFFLINE=1 bash "$SKILL/scripts/sca_scan.sh" code "$FINDINGS/raw/sca" "$FINDINGS"
```

`sca_scan.sh` 构建一份 SBOM（syft，CycloneDX+SPDX），并将依赖版本与
OSV/GHSA/NVD 匹配（osv-scanner 为主；grype/trivy/pip-audit 为辅），为没有清单的内嵌
C/C++ 做指纹识别（`sca_fingerprint.sh`），并通过
`sca_normalize.py` 把一切归一化为 `$FINDINGS/raw/sca/findings.json`（schema `sca-1.0`）。每个工具都是
可选的且会优雅降级——目标机器上没有预装任何一个。

消费 `findings.json`：把 `high`/`medium` 行和 `vendored_unidentified` 提示喂入
LLM 评审与 PoC 阶段。**一个过时的、带有已知内存破坏 CVE 的内嵌库是绝佳的 PoC 目标**——但你仍然
必须产出你自己的 PoC 来确认它（无 PoC ⇒ 未确认）。未经触碰的 `raw/sca/` 目录是可复现的 SCA 记录。

置信度策略（在 `sca_normalize.py` 中）：`high` = ≥2 个检测器一致**或**版本被固定
在一个锁文件级清单中；`medium` = 单个检测器 + 声明清单；`low` = 仅从内嵌指纹推断出的
版本（使用前必须经过佐证）。

---

## 4. SAST（工具）阶段——快速的词法/数据流线索

```bash
bash "$SKILL/scripts/sast_scan.sh" code "$FINDINGS/raw/sast" "$FINDINGS"
# incremental scoping (scoping only, never identity): --changed-from <git-range>
# subtree focus from recon ranking:                   --subtree code/<hot/dir>
```

运行（全部可选、限时、非致命）：Python——`bandit -ll -ii`、`ruff --select
S,B,E9,F`、`semgrep p/python p/security-audit`；C/C++——`flawfinder --minlevel=2`、
`cppcheck --enable=warning,style,performance,portability --inconclusive`、`clang-tidy
clang-analyzer-*,bugprone-*,cert-*`（若存在则使用 `compile_commands.json`）、`semgrep
p/c p/cpp`。可选的 CodeQL 由 `CODEQL=1` 控制（很重；否则由 LLM 阶段覆盖深度污点
情形）。输出：`$FINDINGS/raw/sast/leads.json`（schema `sast-leads-1.0`），
按 `(file, line±2, sink_class)` 去重，并按
`severity × cross-tool-agreement × sink-class-weight` 排序。内存破坏排在
整数溢出之上，整数溢出排在风格瑕疵之上。

---

## 5. LLM 语义 SAST 阶段——深度阶段（这是 AI 体现价值之处）

工具找到的是浅层模式；**你**找到的是多跳污点和缺失的检查。
对每一个高排名的 SAST 线索**以及**来自 recon 的每一个热点单元：

1. 组装**评审单元**：sink 文件加上判断可达性所需的、最小的被展示的被调用者/头文件集合。对你
   所展示的内容精确哈希（`input_manifest`）并记录 `llm_call`。
2. 使用 `templates/reviewer_prompt.md` 运行评审器（两种模式：**Lead-confirm**——取一条
   SAST 线索并确认/驳斥；**Discovery**——找出新缺陷）。Temperature 0。该提示词
   禁止身份/版本/已知 CVE 推理，并要求每个候选项给出：
   - `entry_point`（可达的公共 API / 解析边界），
   - 带有具体 `file:line` 步骤的 `taint_path[]`，
   - `missing_check`（确切缺失的边界/校验），
   - `trigger_hypothesis.concrete_input`，须为**字面取值的**（真实的形状/字节/数字），
   - 单一的、机器可检测的 `poc_oracle`。
3. 为每个候选项发出一个符合 `templates/candidate.schema.json` 的 JSON 对象到
   `$FINDINGS/candidates/`。使用 `templates/sink_taxonomy.md` 中的 sink 类别
   （该 schema 新增了需要本语义阶段的 `narrowing_sign`、`proto_graph`、`ssrf`）。
   你只能把 `status` 设为 `candidate` 或 `refuted`——**绝不**设为 `confirmed`。

---

## 6. Triage 阶段——融合、去重、排序候选项

- 在 `(file, line±2, sink_class)` 上把 SAST `leads.json` 与 LLM `candidates/` 连接；一条
  带有 LLM 污点路径的线索会成为更强的候选项。把没有可达 `entry_point` 的候选项降级到
  `unconfirmed/`（仅线索）。
- 对共享同一 sink 的候选项去重。按 sink 类别权重 × 置信度 × 可达性排序。
- 把排名靠前的候选项带入交叉验证与 PoC。把排序记录为一条 `decision`。

---

## 7. Cross-Validation 阶段——多审计员评审团（仅修剪噪声）

对每个存活的候选项运行一个由独立、无状态、temp-0 阅读组成的**5 视角评审团**：
内存安全、整数溢出、反序列化、并发，以及一个被指示带引用**驳斥**候选项的**红队对手**。确定性地计票：

- **带引用的**对手驳斥胜过无引用的确认 → 候选项以该带引用的理由降级到
  `unconfirmed/`。
- 共识，或有争议但驳斥无引用 → 候选项**升级到 PoC**。

该评审团**只做修剪**——它绝不会把任何东西标记为 `confirmed`。这使其倾向于丢弃
噪声而非制造误报。把每位评审员的阅读记录为一个 `llm_call`；将投票计数存储于
`$FINDINGS/candidates/xval/`。

---

## 8. DAST / PoC 阶段——证明它（通往"已确认"的门禁）

对每个被升级的候选项，搭建一个 finding 并构建一个 AI 生成的复现器：

```bash
FDIR="$(bash "$SKILL/scripts/new_finding.sh" "$FINDINGS" --title "<short>" --sink <class> --severity <SEV>)"
```

按技术栈与判定器挑选 harness：

- **Python API / 原生扩展**——复制 `templates/atheris_harness.py`，填入它的 3 个 SLOT
  （导入目标、`build_input(fdp)` 对抗性 ML 输入、紧凑的 `EXPECTED` 集合）。**关键
  真相：** LD_PRELOAD **不会**对一个已编译的 `.so` 插桩，因此一个现成的预构建扩展产生不了真正的
  原生内存安全证明。要获得真正的原生覆盖，先
  构建一个**已插桩的**目标并验证它：
  ```bash
  bash "$SKILL/scripts/build_sanitized.sh" bazel //path/to:target      # or: so out.so code/unit.cc -- -Icode
  bash "$SKILL/scripts/run_atheris.sh" check-instrumented <module-or-.so>   # must print INSTRUMENTED
  PYTHONPATH=<instrumented-build> FINDINGS_DIR="$FINDINGS" \
    bash "$SKILL/scripts/run_atheris.sh" "$FDIR/poc.py" --time 120 --require-instrumented <module-or-.so>
  ```
  有了 `--require-instrumented`，运行器会在模块未插桩时**中止**，而不是声称获得了原生覆盖。
  （没有它时，仅把 Atheris 用于纯 Python 的崩溃/契约判定器。）
- **C/C++ 单元**——复制 `templates/cpp_fuzz_harness.cc`，填入它的 3 个 SLOT。**最佳：** 链接
  真实的、由 Bazel 构建的目标文件（`build_sanitized.sh bazel`）。**回退**的单单元构建（对未定义引用使用
  弱桩——快速但可能制造真实构建无法触发的崩溃）：
  ```bash
  FINDINGS_DIR="$FINDINGS" bash "$SKILL/scripts/build_cpp_fuzzer.sh" \
      "$FDIR/poc.cc" "$FDIR/fuzz" code/path/unit.cc -- -Icode/include -Icode
  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
      "$FDIR/fuzz" -runs=200000 -max_total_time=120 2>&1 | tee "$FDIR/evidence/run1.log"
  ```
  如果 `$FDIR/fuzz.stubs.json` 非空：把它复制到 `finding.json:stubbed_symbols`，设置
  `needs_real_build_confirmation=true`，并在 **CONFIRMED 之前**用真实构建重跑被最小化的输入
  （并确保没有被打桩的符号位于 `taint_path` 上）。`confirm_finding.sh`
  会阻止一个尚未重新确认的、被打桩的 PoC。
- **数值内核契约缺陷**（新颖的 ML 角度）——复制 `templates/property_test.py`
  （无崩溃鲁棒性、不变式、相对*有充分理由的*参考的差分、蜕变）。它加载一个
  **去随机化的** Hypothesis 配置（无样例数据库），使发现可复现。标签为
  `ORACLE-VIOLATION` / `INVARIANT-VIOLATION` / `DIFFERENTIAL-MISMATCH` / `METAMORPHIC-VIOLATION`
  （triage 把它们映射为 `invariant_violation` / `differential_mismatch` / `metamorphic_violation`）。
  当 Hypothesis 找到一个反例时，**冻结它**：把最小输入写入
  `$FDIR/failing_input.txt`（`AIVH_REGRESSION`），并编写一个独立的 `poc.py`，它在该字面输入上调用
  内核并断言判定器——`run.sh` 重放它 3 次。把
  `finding.json:cited_kernel` 设为该内核的 `code/file:line`，把 `failing_input` 设为
  种子。纯粹的末位 ULP 差分漂移是一条 UNCONFIRMED 线索，绝不是缺陷。

然后分诊并**在判定器上门控**（门禁因证据类别而异）：

```bash
FINDINGS_DIR="$FINDINGS" bash "$SKILL/scripts/triage_crash.sh" "$FDIR/evidence/run1.log" \
    --input "$FDIR/crash-input" --binary "$FDIR/fuzz" --minimize > "$FDIR/oracle.json"
```

`triage_crash.sh` 对证据分类并计算一个**抗重构的 `stack_hash`**。门禁：

- **memory / signal / abort / check** 判定器必须有一个位于 `code/` **内部**的原生崩溃帧
  （`oracle.has_code_frame==true`）——拒绝仅来自 harness 的产物。
- **contract** 判定器（不变式 / 差分 / 蜕变）没有原生帧，因此它们改为
  在 `cited_kernel` + 一份记录在案的 `failing_input` + 确定性重放上门控。
- 在**所有**情况下，判定器都必须**确定性地触发 3 次**——捕获 `evidence/run{1,2,3}.log`。

填写 `finding.json`（`status="CONFIRMED"`、`poc`、3 份 `evidence` 日志、`oracle`），然后**让
执行者来决定**——不要手动翻转为 CONFIRMED：

```bash
bash "$SKILL/scripts/confirm_finding.sh" validate "$FDIR"   # PASS => stays CONFIRMED; FAIL => auto-demoted
```

`confirm_finding.sh` 依据 `templates/finding.schema.json` 校验，**对每一份证据日志独立地重跑
triage**，并要求 ≥3 次复现出相同的判定器（对原生缺陷还要求相同的 `stack_hash`），并执行上面的
类别特定规则。任何失败都会把
`status` 改写为 UNCONFIRMED 并把该 finding 移到 `unconfirmed/`。然后写出 `run.sh` 并从
`templates/finding.md` 填写 `finding.md`。

---

## 9. Severity 评分阶段

对每个已确认的 finding 计算一个有文档记录的、纯粹的、可重新计算的、库上下文 CVSS 风格的
分数 → `$FINDINGS/findings/VH-NNNN/score.json`：

- 把 `sink_class` → CWE 与基础影响映射（内存写入/RCE 类最高；DoS/abort 中等；
  契约违反按数据影响）。
- `score = clamp(impact × AV × AC × PR, 0, 10)`，其中 AV/AC/PR 是来自
  可达性（网络/远程输入 vs. 本地）、触发复杂度与所需权限的、被钳制的乘子。
- 分段：9.0–10 CRITICAL，7.0–8.9 HIGH，4.0–6.9 MEDIUM，<4 LOW。记录确切的输入，使
  分数能恒等地重新计算——这是可复现性记录的一部分。

---

## 10. Report 阶段

从 `templates/REPORT_TEMPLATE.txt` 写出 `$FINDINGS/REPORT.md`：

1. 范围与方法（目标仅以 `target_tree_sha256` 标识——无名称/版本）。
2. 可复现性（指向 `ledger.jsonl` + `env_manifest.json`；运行 `ledger.sh verify`）。
3. **已确认的发现**，按分数排序，每条带一条单命令复现（`findings/VH-NNNN/run.sh`）。
4. 未确认的线索（作为线索上报，明确**不是**缺陷）。
5. SCA 依赖暴露（组件级）。
6. 黑盒合规声明（被看到但未被读取的身份文件；任何记录中均无泄露）。

**在写第 3 节之前，对每个 finding 门控**——一个未通过证明门禁的 finding 不得
发布：

```bash
bash "$SKILL/scripts/confirm_finding.sh" gate-all "$FINDINGS"   # demotes any bad CONFIRMED; non-zero if any failed
```

最后验证记录以及所有交付物的黑盒合规性：

```bash
bash "$SKILL/scripts/ledger.sh" verify "$FINDINGS"                                  # chain intact
bash "$SKILL/scripts/blackbox_guard.sh" scan-file "$FINDINGS/REPORT.md"             # report: no identity leak
for b in "$FINDINGS"/blobs/*; do bash "$SKILL/scripts/blackbox_guard.sh" scan-file "$b" --strict || \
  echo "LEAK in blob $b — investigate"; done                                        # prompts/responses: strict
```

---

## 规模纪律（适用于每个阶段）

- 用 `Glob`/`Grep` 定位攻击面；**绝不通读整棵树**。先排序，再采样。
- 给每个工具设界（`timeout`、`-max_total_time`、文件上限）。工具是可选的且
  非致命——降级，绝不中止流水线。
- 增量地划定范围（`--subtree`、`--changed-from`，*仅用于划定范围*）。
- 把原始工具输出原封不动地保留在 `raw/` 中——它是可复现性证据。

## 脚本（全部位于 `$SKILL/scripts/` 之下，全部非致命 + 账本记录）

- `ledger.sh`（init/append/verify，哈希链式）、`blackbox_guard.sh`（+ `blackbox_denylist.txt`）、
  `selftest.sh`（整个回路的预检证明）。
- SCA：`sca_install.sh`、`sca_scan.sh`、`sca_fingerprint.sh`、`sca_normalize.py`。
- SAST：`sast_scan.sh`、`sast_merge.py`。
- DAST：`build_sanitized.sh`（已插桩的真实构建——首选）、`build_cpp_fuzzer.sh`
  （单单元回退，记录桩的来源）、`run_atheris.sh`（验证插桩）、
  `triage_crash.sh`（分类 + stack_hash）、`new_finding.sh`（脚手架）、
  **`confirm_finding.sh`（被执行的证明门禁——`validate` / `gate-all`）**。

## Schema 与模板（即契约——被引用，不被重复）

- LLM 候选项：`templates/candidate.schema.json`（poc_oracle 词表 == triage evidence_type）。
- 已证明的 finding：`templates/finding.schema.json`（CONFIRMED 需要 poc+evidence+oracle.confirmed）。
- SCA finding：schema `sca-1.0`（在 `sca_normalize.py` 中）；SAST 线索：`sast-leads-1.0`。
- 评审器提示词：`templates/reviewer_prompt.md`。Sink 分类法：`templates/sink_taxonomy.md`。
- Harness：`templates/atheris_harness.py`、`templates/cpp_fuzz_harness.cc`、
  `templates/property_test.py`。Finding/报告：`templates/finding.md`、
  `templates/REPORT_TEMPLATE.txt`。可运行示例：`examples/oob_demo/`。

## 三条规则，重申（绝不违反）

1. **可复现性：** 在每一步追加到 `ledger.jsonl`；对每个提示词/响应数据块内容寻址；temp-0；固定模型 id。
   工具确定性地重放；LLM 步骤被记录，而非种子化。
2. **黑盒：** 绝不读取/说出宿主身份或版本；通过 `blackbox_guard.sh` 门控路径/git；
   在交付前用 `--strict` 扫描提示词数据块以及最终报告。
3. **证明：** 没有触发机器可检测判定器的 AI 生成 PoC ⇒ `UNCONFIRMED`，绝不上报。
   状态由 `confirm_finding.sh` 决定，而非手动决定。

## 11. Phase Deliverables (competition export)

在 Report 阶段结束、发现已由门禁确认（`confirm_finding.sh` 通过、状态 `CONFIRMED`）之后，
运行一条命令即可从 `findings/` 目录导出三份参赛交付物：

```bash
"$SKILL/scripts/make_deliverables.sh" <findings_dir> <out_dir>
# 例：make_deliverables.sh findings/findings findings/deliverables
```

`<findings_dir>` 是直接包含 `VH-*/finding.json` 的目录；脚本会在该目录及其父目录中查找
`ledger.jsonl`、`env_manifest.json`、`REPORT.md`。需要 `jq`；任一输入缺失时优雅降级（写占位或空历史），
不会中断。产出（写入 `<out_dir>`）：

- **`vulnerability_list.md`** — 逐条漏洞清单，由 `templates/vulnerability_list.md` 模板渲染。
  字段取自每个 `finding.json`：**漏洞类型**（`sink_class` + `cwe`）、**严重级别**（`severity`
  + `cvss.score`）、**问题源码路径**（`file:line`，附 `cited_kernel` sink）、**成因简述**
  （`missing_check`）、**与 LLM 交互中哪句提示词发现了 bug**（`notes`，缺省时用薄算子封装通用提示词）、
  **为什么选择此提示词**、**潜在业务危害**（按 `sink_class` 生成的 DoS/内存安全影响句）。
- **`vulnerability_report.md`** — 人类可读报告，由 `findings/REPORT.md` 复制/重命名而来。
- **`llm_chat_log.json`** — 主交付物是**审计模型的真实多轮对话**（`metadata`：`llm_model_used`、
  `total_turns`=对话轮数、黑盒 `system_prompt`；`chat_history`：逐轮 `{turn, role, content}`，
  忠实、可复现地重现黑盒发现过程：定策略 → 崩溃扫描 → 源码根因 → AI 生成 PoC）。
  若 `<out_dir>` 已存在该文件，脚本会**校验并保留**它，同时把由 `ledger.jsonl` 还原的机器记录
  写入 `llm_chat_log.ledger.json`（作为哈希链审计侧证）；若不存在，则以 ledger 还原稿作为初稿，
  待用模型真实提示词/回复补全。全程经 `jq` 保证为合法 JSON。

脚本结束会打印一份写入摘要（各文件状态、解析到的输入路径、发现条数）。

**黑盒规则（同样适用于这三份交付物）**：脚本只读取 `finding.json` / `ledger.jsonl` /
`env_manifest.json` / `REPORT.md`——它们本身已是黑盒产物（不含项目名/版本/CVE 断言）。导出物中
**绝不**断言目标身份或版本、**绝不**引用任何 CVE 或“已知漏洞”。其中出现的 API/PoC 代码
（如 `tf.raw_ops.*`）与源码文件路径均为**发现的客观事实**，属缺陷定位而非身份断言。
身份文件（`AUTHORS`/`RELEASE.md`/`SECURITY.md`）始终仅按路径记录、内容未读。
