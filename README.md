# 基于 AI 的漏洞挖掘 — AI-Based Vulnerability Mining

An engineering-grade, **black-box**, **evidence-driven** vulnerability-discovery system, packaged as
a reusable [Claude Code skill](.claude/skills/ai-vuln-hunt/SKILL.md). You point it at any codebase
placed in `code/`, and it runs a full pipeline — **SCA + SAST tooling + deep LLM semantic analysis +
DAST/fuzzing** — where **every reported bug is proven by an AI-generated, runnable PoC**, and the
**entire AI interaction is captured in a tamper-evident, reproducible audit trail**.

This repository's deliverable is the skill itself: a methodology encoded as an executable runbook
plus the scripts and templates that enforce it.

---

## How it satisfies the competition requirements

| # | Requirement | How the skill meets it |
|---|-------------|------------------------|
| 1 | **Complete, ≥90%-reproducible record of the entire AI interaction** | A hash-chained append-only ledger (`ledger.jsonl`) records every step; every prompt/response/tool-output is content-addressed by SHA-256 under `blobs/`; `env_manifest.json` pins tool/model versions and a source-only `target_tree_sha256`. `ledger.sh verify` recomputes the chain and detects any 1-byte edit. Determinism is framed **honestly**: tools replay exactly; LLM steps are fully logged (not claimed bit-reproducible); findings are PoC-gated so a confirmed bug reproduces via its PoC regardless of run. |
| 2 | **Strict black-box: never told the project, version, or known bugs** | `blackbox_guard.sh` is a hard gate: it default-denies `.git/` and host-identity files (`VERSION`, `CHANGELOG`, `RELEASE`, …), allowlists only `git diff/status/ls-files`, and **blocks** any text that asserts host identity/version (English **and** Chinese) or ties a CVE to host code — exiting non-zero so the run aborts. SCA on third-party *dependencies* stays allowed (that inspects component identity, never the host). Identity by **content hash only**. |
| 3 | **Prove every bug is real; any test must be AI-generated** | "No PoC, no bug." `confirm_finding.sh` is an **enforced** gate: it validates each finding against a JSON schema, **independently re-runs triage on every evidence log** and requires ≥3 to reproduce the same machine oracle (ASAN/UBSAN/MSAN/signal/abort/CHECK, or a stated invariant/differential/metamorphic violation), and auto-**demotes** anything unproven to `unconfirmed/`. All PoCs/tests are AI-generated. |
| 4 | **Maximize the LLM; combine traditional + novel methods (bonus)** | Traditional SCA/SAST/DAST are fused with **LLM semantic SAST** (multi-hop taint + missing-check reasoning), a **multi-auditor cross-validation panel** (memory-safety / integer-overflow / deserialization / concurrency / red-team), and the **novel ML angle**: invariant / differential / metamorphic property testing of numeric kernels, which finds contract bugs a fuzzer alone misses. |

---

## The pipeline

```
Recon ─▶ SCA ─▶ SAST (tools) ─▶ LLM semantic SAST ─▶ Triage ─▶ Cross-validation ─▶ DAST/PoC ─▶ Score ─▶ Report
 auto-detect    SBOM + OSV/    bandit/semgrep/      sink taxonomy   fuse + dedup   5-lens panel   PROVE with    CVSS-   confirmed-
 + rank the     NVD/GHSA       cppcheck/clang-tidy  + reviewer      candidates     (prunes noise) AI PoC +      style   only,
 attack surface (deps only)    + flawfinder         protocol                                      oracle gate           reproducible
```

- **Scale-aware**: it never reads the whole tree — it ranks the attack surface and samples; tools are
  time-boxed, optional, and non-fatal.
- **Gates between phases**: a candidate without a reachable entry point, or a finding without a
  reproducing PoC, never advances. The cross-validation panel only *prunes*; the **PoC is the sole
  arbiter** of "confirmed."

## Using it

```bash
# 1) Put the target under code/ (the skill treats it as an unknown black box).
# 2) Invoke the skill in Claude Code:
/ai-vuln-hunt
# 3) Outputs land in findings/: ledger.jsonl, env_manifest.json, sbom/, raw/, candidates/,
#    findings/VH-NNNN/ (proof packages), unconfirmed/, and REPORT.md.
```

The runbook Claude follows is [`.claude/skills/ai-vuln-hunt/SKILL.md`](.claude/skills/ai-vuln-hunt/SKILL.md).

## Proof that the machinery works

```bash
bash .claude/skills/ai-vuln-hunt/scripts/selftest.sh     # => "13 pass, 0 fail"
```

The selftest builds a real out-of-bounds-write target, generates a PoC, triggers a genuine ASAN
crash, triages it, scaffolds a finding, and runs the proof gate to CONFIRMED — then proves a **forged**
CONFIRMED finding is automatically demoted. A captured, self-consistent run lives in
[`.claude/skills/ai-vuln-hunt/examples/oob_demo/`](.claude/skills/ai-vuln-hunt/examples/oob_demo/)
(its `finding.json` passes `confirm_finding.sh` on a clean checkout).

## Layout

```
.claude/skills/ai-vuln-hunt/
  SKILL.md                  # the end-to-end runbook (the methodology)
  scripts/                  # ledger, blackbox_guard, SCA/SAST/DAST tooling, confirm_finding, selftest
  templates/                # reviewer prompt, sink taxonomy, harnesses, JSON schemas, report
  examples/oob_demo/        # a captured, gate-passing worked example
code/                       # (you add) the target codebase — treated as a black box
findings/                   # (generated) the reproducible audit trail + proof packages + REPORT.md
```
