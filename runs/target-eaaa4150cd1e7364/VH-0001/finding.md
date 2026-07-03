# VH-0001 — raw_ops.ThreadPoolHandle num_threads=0 reachable CHECK abort (DoS)

- **Status:** UNCONFIRMED  <!-- 仅在获得 PoC + oracle 证据后才变为 CONFIRMED -->
- **Sink class:** availability
- **Severity:** MEDIUM
- **CWE:** TBD
- **Location:** `code/<file>:<line>`

## 摘要
用一段话说明：以代码层面描述缺陷是什么，不涉及项目身份或版本。陈述被违反的不变量或被破坏的内存安全规则。

## 入口点与可达性
- 外部调用者可以到达的公共 API / 解析边界：
- 受污染的值为何会从那里流向 sink（黑盒推理）：

## 污点路径
1. `code/<file>:<line>` — 值进入 / 被读取
2. `code/<file>:<line>` — 被传播 / 发生溢出或跳过检查的算术运算
3. `code/<file>:<line>` — **sink**：此处缺失的边界 / 校验

## 缺失的检查
本应存在但实际不存在的确切校验（例如 `dim >= 0`、`offset + len <= buffer_size`、`axis < rank`）。

## 概念验证
- **PoC file:** `poc.<ext>`（AI 生成；描述它构造了什么）
- **Oracle:** ASAN / UBSAN / SIGSEGV / abort / invariant-violation（任选其一）
- **Run:** `./run.sh`
- **Evidence:** `evidence/run1.log`、`evidence/run2.log`、`evidence/run3.log`
  （oracle 必须在全部三次运行中确定性地触发）

```
<粘贴 sanitizer/oracle 报告中关键的几行，包括 code/ 内的顶层应用栈帧 —— 这正是证明该漏洞真实存在的依据>
```

## 严重性论证
在库上下文下的影响 x 可利用性。评分：参见 `score.json`（由脚本重新计算：影响 x 钳制后的 AV/AC/PR -> 0-10 区间）。

## 备注
交叉验证小组标记出的任何内容；红队反驳为何未能成立。
