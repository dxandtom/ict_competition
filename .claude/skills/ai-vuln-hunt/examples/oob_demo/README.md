# 完整示例 —— 越界写（OOB write），发现 → 证明 → 确认

这是该技能证明循环的一次**真实、已捕获的运行记录**（由 `scripts/selftest.sh` 生成），
准确展示了一个 CONFIRMED 结论是什么样子，以及证明关卡是被强制执行的 —— 而不仅仅是
口头描述。为便于移植，绝对路径被重写为 `<WORKDIR>`；其余内容没有改动。

## 目标程序（`code/vuln.c`）
一个 `write_at()` 辅助函数将一个字节存入 `buf[idx]`，**没有任何边界检查**，可从持有 16 字节栈
缓冲区的 `parse_and_store()` 中触达。任何 `idx >= 16` 都是一次越界写。

## AI 生成的 PoC（`poc.c`）
一个最小化的独立复现程序，调用 `parse_and_store(20)` —— `idx = 20` 落入 AddressSanitizer 的
红区（redzone），产生一个干净、确定性的 `stack-buffer-overflow`。

## 证据（`evidence/run1.log`）
ASAN 报告。顶层栈帧**位于 `code/` 内部**（`write_at code/vuln.c:3`、
`parse_and_store code/vuln.c:6`）—— 这正是它成为目标程序中真实缺陷、而非测试框架自身假象的
依据。该 PoC 运行了 **3 次**；三次运行复现出完全相同的报告。

## 分类研判（`oracle.json`）
`triage_crash.sh` 对报告进行了分类：`evidence_type=asan`、`sink_class=oob_rw`、
`cwe=CWE-787/125`、`severity=HIGH`、一个对重构稳定的 `stack_hash`、`requires_native_frame=true`、
`has_code_frame=true`、`confirmed=true`。

## 结论（`finding.json`）
`status=CONFIRMED`，携带 `poc`、三份 `evidence` 日志以及 `oracle`。`confirm_finding.sh`
**对每一份证据日志独立地重新运行了分类研判**，并要求三份全部复现出相同的 oracle
（相同的 `evidence_type`、相同的 `stack_hash`）后才允许判定为 CONFIRMED —— 而对于内存类
oracle，还要求 `has_code_frame=true`。

## 账本（`ledger_excerpt.jsonl`）
哈希链审计轨迹的最初若干条记录。每条记录都携带 `payload_sha256` 和
`chain_sha256`；`ledger.sh verify` 会重新计算整条链，自检（selftest）证明哪怕 1 字节的改动也会
被检测到。

## 自行复现
```bash
bash ../../scripts/selftest.sh /tmp/aivh_demo
# => 13 pass, 0 fail; inspect /tmp/aivh_demo/findings/findings/VH-0001/
```
自检的负向部分还证明了一个**伪造的** `status=CONFIRMED` 结论（没有 PoC、空 oracle）
会被自动**降级为 UNCONFIRMED** 并移入 `unconfirmed/`。
