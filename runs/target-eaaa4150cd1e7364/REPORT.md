# 漏洞发现报告

> 由 `ai-vuln-hunt` 技能生成。黑盒、以证据为准。仅 PoC 已证明的发现出现在第 3 节；
> 其余作为未确认线索。运行者从未被告知目标的名称/版本/已知缺陷。

## 1. 范围与方法
- **目标**：仅以源码内容哈希标识 —— `target_tree_sha256 = eaaa4150cd1e7364…`（对
  16,658 个源文件的清单计算），见 `env_manifest.json`。目标的名称与版本从未被读取或使用。
  被识别但**未读取**的身份文件（路径记录、内容未读）：`code/AUTHORS`、`code/RELEASE.md`、
  `code/SECURITY.md`。
- **技术栈（自动识别）**：Python（2,906 文件）+ C/C++（11,943 文件），Bazel 构建。
- **方法**：Recon（对攻击面排序、采样，不通读）→ SCA（依赖成分）→ SAST（工具）→
  LLM 语义审查 → 候选分诊 → DAST/PoC 证明 → 强制门禁 → 评分。
- **优先攻击面（黑盒推理）**：`raw_ops.*` 这类薄封装算子，把调用者可控的形状/索引/分片/
  线程数等元数据直接传入 C++ 内核，Python 侧校验最少 —— 历史上是数值/ML 库最脆弱的入口。

## 2. 可复现性
- 完整的哈希链交互账本：`ledger.jsonl`（23 条记录，`ledger.sh verify` 校验：**链完整**）。
- 环境 + 精确工具/模型版本：`env_manifest.json`；提示词/工具输出按 SHA-256 存于 `blobs/`。
- 所有工具原始输出未经改动地保存在 `raw/` 下。
- 确定性（如实表述）：工具输入/输出按内容寻址、可精确重放；LLM 步骤温度为 0、被完整记录，
  但不逐比特可复现；发现受 PoC 门控，故每个已确认缺陷都可经其 PoC 确定性复现。

## 3. 已确认发现（按评分排序）

| ID | 标题 | 类别 | 严重度 | CWE | Oracle | 一键复现 |
|----|------|------|--------|-----|--------|----------|
| VH-0001 | `raw_ops.ThreadPoolHandle(num_threads=0)` 可达 CHECK abort（DoS） | availability | MEDIUM (4.0) | CWE-617 | abort/CHECK | `findings/VH-0001/run.sh` |
| VH-0002 | `raw_ops.RecordInput(file_parallelism=2**31)` int64→int32 窄化致负线程数 → CHECK abort | int_overflow | MEDIUM (4.0) | abort/CHECK | CWE-197/617 | `findings/VH-0002/run.sh` |

### VH-0001 — ThreadPoolHandle：num_threads=0 越过校验命中致命 CHECK
- **入口**：公开算子 `tf.raw_ops.ThreadPoolHandle`（`ExperimentalThreadPoolHandle` 同因）。
- **污点路径**：
  1. `tensorflow/core/kernels/data/experimental/threadpool_dataset_op.cc:47`
     `ValidateNumThreads` 拒绝 `num_threads<0` 和 `>=kThreadLimit`，**但接受 `==0`**。
  2. 该校验通过后，以 `num_threads=0` 构造 `ThreadPoolResource`。
  3. `tensorflow/tsl/platform/threadpool.cc:100` `ThreadPool` 构造函数
     `CHECK_GE(num_threads, 1)` 失败 → `LOG(FATAL)`/abort（整个进程崩溃）。
- **缺失的检查**：校验器允许 0，而 `ThreadPool` 要求 `>=1`；该边界用致命 `CHECK` 而非可返回的
  `OP_REQUIRES` 错误来处理（off-by-one）。
- **证据**：3/3 次运行复现 `F …/threadpool.cc:100] Check failed: num_threads >= 1 (1 vs. 0)`，
  进程 SIGABRT（rc=134）。见 `findings/VH-0001/evidence/run{1,2,3}.log`、`oracle.json`。

### VH-0002 — RecordInput：file_parallelism 整数窄化为负线程数
- **入口**：公开算子 `tf.raw_ops.RecordInput(file_pattern="/tmp/none", file_parallelism=2**31)`。
- **污点路径**：
  1. `tensorflow/core/kernels/record_input_op.cc:37` `file_parallelism` 以 `int64_t` 读入，
     无正数/上界校验。
  2. `record_input_op.cc:49` `yopts.parallelism = file_parallelism`（int64）向下游传递。
  3. 下游窄化为 32 位线程数：`2**31` 回绕为 `-2147483647`；`tensorflow/tsl/platform/threadpool.cc:100`
     `CHECK_GE(num_threads, 1)` 失败 → abort。
- **缺失的检查**：`file_parallelism` 无正数/上界校验，且 int64→int32 窄化未做防溢出处理。
- **证据**：3/3 次运行复现 `Check failed: num_threads >= 1 (1 vs. -2147483647)`，SIGABRT。
  见 `findings/VH-0002/evidence/run{1,2,3}.log`。

> 两者均由黑盒 `raw_ops` 崩溃扫描（`findings/raw/dast/`，隔离子进程 + 崩溃后续跑）发现，
> 再通过阅读**目标源码**确认根因，最后由 `confirm_finding.sh` 对每份证据独立重跑分诊、
> 要求 3/3 复现一致方判为 CONFIRMED。

## 4. 未确认线索（无 PoC —— 仅作线索，非缺陷）
- `LearnedUnigramCandidateSampler`（极端 `range_max/num_sampled=2**31`）在扫描中触发进程
  中止，但尚未定位到 code/ 内的确定崩溃位置，按门禁规则**未确认**，不作为缺陷上报。
- 崩溃扫描的完整原始结果见 `findings/raw/dast/crashes.jsonl`、`sweep_results.jsonl`。

## 5. SAST（静态工具，真实运行）
- 对高风险子树 `code/tensorflow/core/kernels/data` 运行 flawfinder（minlevel=3）：**383** 处提示；
  bandit 扫描 Python 侧。原始输出：`raw/sast/`。这些是待人工/LLM 复核的线索，非已证明缺陷。

## 6. SCA（软件成分分析）
- 对依赖闭包运行 pip-audit（`raw/sca/`）。本沙箱中解析到的依赖为较新版本，未匹配到已知 CVE；
  面向真实部署时应针对目标实际固定的依赖版本与 `third_party/` 内置组件版本重新扫描（组件级，
  不涉及宿主身份）。

## 7. 黑盒合规声明
- 身份文件仅按路径记录、内容未读，见 `env_manifest.json:identity_files_seen_but_unread`。
- 未在任何提示词、命令或账本记录中对宿主目标做“项目名/版本/已知 CVE”的断言
  （`blackbox_guard.sh` 强制执行并记录）。报告中出现的文件路径为目标代码自身的目录结构，
  属客观的缺陷定位，不构成身份断言。
