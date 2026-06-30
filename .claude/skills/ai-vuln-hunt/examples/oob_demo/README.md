# Worked example — OOB write, discovered → proven → confirmed

This is a **real, captured run** of the skill's proof loop (produced by `scripts/selftest.sh`),
showing exactly what a CONFIRMED finding looks like and that the proof gate is enforced — not
just described. Absolute paths were rewritten to `<WORKDIR>` for portability; nothing else changed.

## The target (`code/vuln.c`)
A `write_at()` helper stores a byte at `buf[idx]` with **no bounds check**, reachable from
`parse_and_store()` which holds a 16-byte stack buffer. Any `idx >= 16` is an out-of-bounds write.

## The AI-generated PoC (`poc.c`)
A minimal standalone reproducer calling `parse_and_store(20)` — `idx = 20` lands in AddressSanitizer's
redzone, producing a clean, deterministic `stack-buffer-overflow`.

## The evidence (`evidence/run1.log`)
The ASAN report. The top frames are **inside `code/`** (`write_at code/vuln.c:3`,
`parse_and_store code/vuln.c:6`) — this is what makes it a real defect in the target rather than a
harness artifact. The PoC was run **3×**; all three runs reproduce the identical report.

## The triage (`oracle.json`)
`triage_crash.sh` classified the report: `evidence_type=asan`, `sink_class=oob_rw`,
`cwe=CWE-787/125`, `severity=HIGH`, a refactor-stable `stack_hash`, `requires_native_frame=true`,
`has_code_frame=true`, `confirmed=true`.

## The finding (`finding.json`)
`status=CONFIRMED` carrying `poc`, three `evidence` logs, and the `oracle`. `confirm_finding.sh`
**re-ran triage on every evidence log independently** and required all three to reproduce the same
oracle (same `evidence_type`, same `stack_hash`) before allowing CONFIRMED — and for a memory
oracle, required `has_code_frame=true`.

## The ledger (`ledger_excerpt.jsonl`)
The first records of the hash-chained audit trail. Each record carries `payload_sha256` and
`chain_sha256`; `ledger.sh verify` recomputes the chain and the selftest proves a 1-byte edit is
detected.

## Reproduce it yourself
```bash
bash ../../scripts/selftest.sh /tmp/aivh_demo
# => 13 pass, 0 fail; inspect /tmp/aivh_demo/findings/findings/VH-0001/
```
The negative half of the selftest also proves a **forged** `status=CONFIRMED` finding (no PoC, empty
oracle) is automatically **demoted to UNCONFIRMED** and moved to `unconfirmed/`.
