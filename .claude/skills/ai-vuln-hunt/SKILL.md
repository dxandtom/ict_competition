---
name: ai-vuln-hunt
description: Use this skill to perform black-box, evidence-driven vulnerability discovery on a target codebase placed in code/, combining SCA + SAST tooling + DAST/fuzzing with deep LLM semantic analysis, where every reported bug is proven by an AI-generated runnable PoC and the entire AI interaction is captured in a reproducible, hash-chained audit trail.
---

# AI-Based Vulnerability Hunting (基于AI的漏洞挖掘)

You are running a systematic, engineering-grade vulnerability-hunting pipeline against a
**target codebase that lives in the local `code/` directory**. You combine traditional
techniques (SCA, SAST, DAST/fuzzing) with deep LLM semantic analysis, and you **PROVE**
every reported bug with a runnable, AI-generated Proof-of-Concept (PoC).

This file is your end-to-end runbook. Follow it in order. It is target-agnostic: you
**auto-detect** the stack and adapt. The codebase may be multi-million lines — you must
**triage, prioritize, and sample**; you must **never** try to read everything.

Establish two variables once at the start of the session:

```bash
SKILL="$(dirname "$(find . -path '*ai-vuln-hunt/SKILL.md' | head -1)")"   # this skill dir
FINDINGS="$(cd code/.. && pwd)/findings"                                  # output root: code/../findings
chmod +x "$SKILL"/scripts/*.sh 2>/dev/null || true
```

All scripts are in `$SKILL/scripts/`, all templates in `$SKILL/templates/`. This runbook
**references** them; it does not duplicate their contents.

---

## 0. THREE NON-NEGOTIABLE CONTRACTS (read before anything else)

### 0.1 Black-box contract — what you must NOT do

The operator will **never** tell you what the project is, its version, or that any specific
bug exists. Discover everything **from the code itself**. Therefore:

- **DO NOT read, open, grep, or pass to any tool/prompt** these *host-identity* files:
  `VERSION`, `version.txt`, `CHANGELOG*`, `RELEASE*`, `NEWS`, `HISTORY*`, `SECURITY.md`,
  `NOTICE`, `AUTHORS`, `CONTRIBUTORS`, in-repo security advisories, and anything under
  `.git/`. If you stumble on one, record its path in
  `env_manifest.json:identity_files_seen_but_unread` and move on.
- **DO NOT** run `git tag`, `git log`, `git describe`, `git blame`, or read git history to
  infer the project identity/version. `git diff RANGE` is allowed **only** for scoping.
- **DO NOT** state, write, or prompt with any sentence asserting "this project is X version
  Y", "this is a known CVE/bug", or "this version is vulnerable to …" about the **host**
  target. Reason only from the code in front of you.
- **ALLOWED:** SCA on third-party **dependencies** — reading dependency manifests
  (`requirements*.txt`, `pyproject.toml`, `WORKSPACE`, `MODULE.bazel`, `third_party/**`) and
  a dependency's **own** embedded version markers, and matching `(component, version)`
  against OSV/NVD/GHSA. That inspects *component* identity, never *host* identity.

Enforcement is mechanical (`blackbox_guard.sh`), and it is a **hard gate**, not best-effort:

- `check-path <p>` default-**denies** any path with a `.git` component and any host-identity
  basename (`VERSION*`, `CHANGELOG*`, `CHANGES*`, `RELEASE*`, `SECURITY*`, `*.bazel` version
  files, …) while whitelisting dependency manifests. **Call it before any `Read`/`Glob` target you
  are unsure about, and never bulk-`Read`.**
- `check-git <args>` is an **allowlist**: only `diff|status|ls-files` for scoping; `tag`, `log`,
  `describe`, `rev-parse`, `blame`, `show`, … are denied.
- `scan-file <f>` / `scan-stdin` exit **non-zero (4)** on a host-identity assertion (EN or ZH),
  a host vuln claim, or a CVE tied to host code. Use **`--strict`** when scanning prompt blobs
  before you log them (it additionally blocks any bare project NAME from `blackbox_denylist.txt`);
  use default mode for `REPORT.md` (lets bare dependency names through for SCA, still blocks
  assertions). A non-zero exit means **abort and fix**, do not continue.
- Every `ledger.sh` summary is auto-scanned and redacted if it would leak.

Run `bash "$SKILL/scripts/blackbox_guard.sh" selftest` and `bash "$SKILL/scripts/selftest.sh"`
once at the start to confirm the guard and the whole proof loop work before you trust them.

### 0.2 Reproducibility contract — capture EVERYTHING

You must produce a **complete, untampered, ≥90%-reproducible** record of the entire AI
interaction. Mechanism:

- A hash-chained append-only ledger at `$FINDINGS/ledger.jsonl`. **Append a record at every
  step** (instruction, tool_call, llm_call, decision, artifact, note) via
  `bash "$SKILL/scripts/ledger.sh" append "$FINDINGS" --phase P --actor A --kind K --summary S [--blob FILE]...`.
- Large blobs (prompts, tool argv, model responses, stdout) are content-addressed under
  `$FINDINGS/blobs/<sha256>` and referenced by hash — never inlined — so the ledger stays
  small on a multi-MLOC target.
- LLM steps record the exact `model` id, `temperature:0`, and the `input_manifest`
  (`path::sha256` of exactly what code was shown) plus the FULL prompt **and** response as
  content-addressed blobs. Use **temperature 0** for every analysis call.
- `env_manifest.json` pins OS/kernel, every tool+python+clang version, the exact model id
  (set `AIVH_MODEL`), and the target **`target_tree_sha256`** (a hash over a manifest of
  *source* files only — never binaries/datasets/identity files; see `target_tree_manifest.txt`).
- `ledger.sh verify "$FINDINGS"` recomputes the chain; a 1-byte edit breaks it at the exact
  record. **Honest reproducibility argument** (see `env_manifest.reproducibility_note`): tool
  inputs/outputs are content-addressed and replay **deterministically**; LLM calls are *not*
  bit-reproducible (no exposed sampling seed) but are **fully logged and re-runnable**; and
  because findings are **PoC-gated**, a confirmed bug reproduces deterministically via its PoC
  regardless of which LLM run surfaced it. Do **not** claim seeded LLM determinism.

### 0.3 Proof contract — no PoC, no bug

Every reported bug MUST be proven by an **AI-generated** minimal reproducer that trips a
**machine-detectable oracle**: ASAN/UBSAN/MSAN report, SIGSEGV/SIGFPE, abort/CHECK/assert
failure, uncaught exception in code that must not throw, or a wrong result vs. an explicitly
stated invariant (differential/metamorphic). If tests exist in the repo you may **not** rely
on them — any test you use as proof must be AI-generated. **No PoC ⇒ status `UNCONFIRMED`,
quarantined under `$FINDINGS/unconfirmed/`, never reported as a bug.** The PoC is the *sole*
arbiter; the cross-validation panel only prunes noise, it never promotes to confirmed.

---

## 1. Preflight + output layout (do this first)

```bash
# Preflight: prove the machinery (guard + ledger chain + full PoC->confirm loop) works.
bash "$SKILL/scripts/blackbox_guard.sh" selftest
bash "$SKILL/scripts/selftest.sh"                          # expect "N pass, 0 fail"
export AIVH_MODEL="<exact-model-id>"                       # pin the model for the record
bash "$SKILL/scripts/ledger.sh" init "$FINDINGS" code
```

This creates and the rest of the run populates:

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

Append a `decision` ledger record at each phase boundary so the gate is auditable.

---

## 2. Phase Recon — auto-detect stack, map high-risk surface (DO NOT read everything)

Goal: a ranked map of attack surface, not a full read. Use `Glob`/`Grep`, never bulk `Read`.

1. **Detect stack** (record as a ledger note):
   - Python: `Glob code/**/*.py`, presence of `requirements*.txt`/`pyproject.toml`/`setup.py`.
   - C/C++: `Glob code/**/*.{c,cc,cpp,h,hpp}`; build system via `WORKSPACE`/`MODULE.bazel`/
     `BUILD`/`CMakeLists.txt`/`Makefile`.
   - Native extension boundary (highest value): `Grep -n "PyModule_|PYBIND11_|pybind11|Py_BuildValue|nb::module_"`.
2. **Locate attack surface** with the taxonomy seeds in `templates/sink_taxonomy.md`. Prefer:
   parsers/deserializers (`pickle`, `ParseFromString`, `tarfile`, `yaml.load`), tensor
   index/shape math (`gather`, `scatter`, `reshape`, `stride`, `[idx]`, `data()+`), size
   arithmetic (`* sizeof`, dim products), and any `(int)`/`static_cast<int>` narrowing of
   64-bit dims.
3. **Rank then sample.** Score subtrees by surface density × reachability from a public API.
   Carry forward only the top-ranked units into the LLM pass; record the ranking as a
   `decision` so the triage is reproducible. Never `Read` a file purely to learn identity.

Gate before reading any path: `blackbox_guard.sh check-path <path>`.

---

## 3. Phase SCA — dependency CVE exposure (component identity only)

```bash
bash "$SKILL/scripts/sca_install.sh"                       # ./.sca/bin, warms offline OSV DB
bash "$SKILL/scripts/sca_scan.sh" code "$FINDINGS/raw/sca" "$FINDINGS"
# air-gapped: OFFLINE=1 bash "$SKILL/scripts/sca_scan.sh" code "$FINDINGS/raw/sca" "$FINDINGS"
```

`sca_scan.sh` builds an SBOM (syft, CycloneDX+SPDX) and matches dependency versions against
OSV/GHSA/NVD (osv-scanner primary; grype/trivy/pip-audit secondary), fingerprints vendored
C/C++ that has no manifest (`sca_fingerprint.sh`), and normalizes everything via
`sca_normalize.py` into `$FINDINGS/raw/sca/findings.json` (schema `sca-1.0`). Every tool is
optional and degrades gracefully — none are preinstalled on the target box.

Consume `findings.json`: feed `high`/`medium` rows and `vendored_unidentified` hints into the
LLM-review and PoC phases. **An outdated vendored lib with a known memory-corruption CVE is a
prime PoC target** — but you still must produce your own PoC to confirm it (no PoC ⇒
unconfirmed). The untouched `raw/sca/` directory is the reproducible SCA record.

Confidence policy (in `sca_normalize.py`): `high` = ≥2 detectors agree **or** version pinned
in a lockfile-grade manifest; `medium` = single detector + declared manifest; `low` = version
inferred from a vendored fingerprint only (must be corroborated before use).

---

## 4. Phase SAST (tools) — fast lexical/dataflow leads

```bash
bash "$SKILL/scripts/sast_scan.sh" code "$FINDINGS/raw/sast" "$FINDINGS"
# incremental scoping (scoping only, never identity): --changed-from <git-range>
# subtree focus from recon ranking:                   --subtree code/<hot/dir>
```

Runs (all optional, time-boxed, non-fatal): Python — `bandit -ll -ii`, `ruff --select
S,B,E9,F`, `semgrep p/python p/security-audit`; C/C++ — `flawfinder --minlevel=2`,
`cppcheck --enable=warning,style,performance,portability --inconclusive`, `clang-tidy
clang-analyzer-*,bugprone-*,cert-*` (uses `compile_commands.json` if present), `semgrep
p/c p/cpp`. Optional CodeQL behind `CODEQL=1` (heavy; the LLM pass covers the deep taint
cases otherwise). Output: `$FINDINGS/raw/sast/leads.json` (schema `sast-leads-1.0`),
de-duplicated by `(file, line±2, sink_class)` and ranked by
`severity × cross-tool-agreement × sink-class-weight`. Memory-corruption ranks above
int-overflow ranks above style nits.

---

## 5. Phase LLM Semantic SAST — the deep pass (this is where AI earns its keep)

Tools find shallow patterns; **you** find the multi-hop taint and the missing check.
For each high-ranked SAST lead **and** each hot unit from recon:

1. Assemble the **review unit**: the sink file plus the minimal set of shown callees/headers
   needed to judge reachability. Hash exactly what you show (`input_manifest`) and log the
   `llm_call`.
2. Run the reviewer using `templates/reviewer_prompt.md` (two modes: **Lead-confirm** — take a
   SAST lead and confirm/refute; **Discovery** — find new defects). Temperature 0. The prompt
   FORBIDS identity/version/known-CVE reasoning and demands, per candidate:
   - `entry_point` (reachable public API / parse boundary),
   - `taint_path[]` with concrete `file:line` steps,
   - `missing_check` (the exact absent bounds/validation),
   - `trigger_hypothesis.concrete_input` that is **literal-valued** (real shapes/bytes/numbers),
   - a single machine-detectable `poc_oracle`.
3. Emit one JSON object per candidate conforming to `templates/candidate.schema.json` into
   `$FINDINGS/candidates/`. Use the sink classes from `templates/sink_taxonomy.md`
   (the schema adds `narrowing_sign`, `proto_graph`, `ssrf` that need this semantic pass).
   You may set `status` only to `candidate` or `refuted` — **never** `confirmed`.

---

## 6. Phase Triage — fuse, dedup, prioritize candidates

- Join SAST `leads.json` with the LLM `candidates/` on `(file, line±2, sink_class)`; a lead
  with an LLM taint-path becomes a stronger candidate. Drop candidates with no reachable
  `entry_point` to `unconfirmed/` (lead-only).
- Dedup candidates that share a sink. Order by sink-class weight × confidence × reachability.
- Carry the top candidates into cross-validation and PoC. Record the ordering as a `decision`.

---

## 7. Phase Cross-Validation — multi-auditor panel (prunes noise only)

For each surviving candidate run a **5-lens panel** of independent, stateless, temp-0 reads:
memory-safety, integer-overflow, deserialization, concurrency, and a **red-team adversary**
instructed to *refute* the candidate with a citation. Tally deterministically:

- A **cited** adversary refutation beats uncited confirmations → candidate dropped to
  `unconfirmed/` with the cited reason.
- Consensus or contested-but-uncited-refutation → candidate **escalates to PoC**.

The panel **only prunes** — it never marks anything `confirmed`. This biases toward dropping
noise over manufacturing false positives. Log each panelist read as an `llm_call`; store the
vote tally in `$FINDINGS/candidates/xval/`.

---

## 8. Phase DAST / PoC — PROVE it (the gate to "confirmed")

For each escalated candidate, scaffold a finding and build an AI-generated reproducer:

```bash
FDIR="$(bash "$SKILL/scripts/new_finding.sh" "$FINDINGS" --title "<short>" --sink <class> --severity <SEV>)"
```

Pick the harness by stack and oracle:

- **Python API / native extension** — copy `templates/atheris_harness.py`, fill its 3 SLOTs
  (import target, `build_input(fdp)` adversarial ML inputs, tight `EXPECTED` set). **Crucial
  truth:** LD_PRELOAD does **not** instrument an already-compiled `.so`, so a stock prebuilt
  extension yields no real native memory-safety proofs. To get genuine native coverage, first
  build an **instrumented** target and verify it:
  ```bash
  bash "$SKILL/scripts/build_sanitized.sh" bazel //path/to:target      # or: so out.so code/unit.cc -- -Icode
  bash "$SKILL/scripts/run_atheris.sh" check-instrumented <module-or-.so>   # must print INSTRUMENTED
  PYTHONPATH=<instrumented-build> FINDINGS_DIR="$FINDINGS" \
    bash "$SKILL/scripts/run_atheris.sh" "$FDIR/poc.py" --time 120 --require-instrumented <module-or-.so>
  ```
  With `--require-instrumented`, the runner **aborts** rather than claim native coverage on an
  uninstrumented module. (Without it, use Atheris only for pure-Python crash/contract oracles.)
- **C/C++ unit** — copy `templates/cpp_fuzz_harness.cc`, fill its 3 SLOTs. **Best:** link the
  real Bazel-built objects (`build_sanitized.sh bazel`). **Fallback** single-unit build (weak
  stubs for undefined refs — fast but can manufacture crashes the real build can't):
  ```bash
  FINDINGS_DIR="$FINDINGS" bash "$SKILL/scripts/build_cpp_fuzzer.sh" \
      "$FDIR/poc.cc" "$FDIR/fuzz" code/path/unit.cc -- -Icode/include -Icode
  ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
      "$FDIR/fuzz" -runs=200000 -max_total_time=120 2>&1 | tee "$FDIR/evidence/run1.log"
  ```
  If `$FDIR/fuzz.stubs.json` is non-empty: copy it into `finding.json:stubbed_symbols`, set
  `needs_real_build_confirmation=true`, and **before CONFIRMED** re-run the minimized input
  against the real build (and ensure no stubbed symbol lies on `taint_path`). `confirm_finding.sh`
  blocks a stubbed PoC that hasn't been re-confirmed.
- **Numeric-kernel contract bug** (the novel ML angle) — copy `templates/property_test.py`
  (no-crash robustness, invariant, differential-vs-*justified*-reference, metamorphic). It loads a
  **derandomized** Hypothesis profile (no example DB) so discovery is reproducible. Tags are
  `ORACLE-VIOLATION` / `INVARIANT-VIOLATION` / `DIFFERENTIAL-MISMATCH` / `METAMORPHIC-VIOLATION`
  (triage maps these to `invariant_violation` / `differential_mismatch` / `metamorphic_violation`).
  When Hypothesis finds a counterexample, **freeze it**: write the minimal input to
  `$FDIR/failing_input.txt` (`AIVH_REGRESSION`) and author a standalone `poc.py` that calls the
  kernel on that literal input and asserts the oracle — `run.sh` replays it 3×. Set
  `finding.json:cited_kernel` to the `code/file:line` of the kernel and `failing_input` to the
  seed. Pure last-ULP differential drift is an UNCONFIRMED lead, never a bug.

Then triage and **gate on the oracle** (the gate differs by evidence class):

```bash
FINDINGS_DIR="$FINDINGS" bash "$SKILL/scripts/triage_crash.sh" "$FDIR/evidence/run1.log" \
    --input "$FDIR/crash-input" --binary "$FDIR/fuzz" --minimize > "$FDIR/oracle.json"
```

`triage_crash.sh` classifies the evidence and computes a **refactor-stable `stack_hash`**. The gate:

- **memory / signal / abort / check** oracles MUST have a native crash frame **inside `code/`**
  (`oracle.has_code_frame==true`) — reject harness-only artifacts.
- **contract** oracles (invariant / differential / metamorphic) have no native frame, so they are
  gated on `cited_kernel` + a recorded `failing_input` + deterministic replay instead.
- In **all** cases the oracle must fire **deterministically 3×** — capture `evidence/run{1,2,3}.log`.

Fill `finding.json` (`status="CONFIRMED"`, `poc`, the 3 `evidence` logs, `oracle`), then **let the
enforcer decide** — do not hand-flip to CONFIRMED:

```bash
bash "$SKILL/scripts/confirm_finding.sh" validate "$FDIR"   # PASS => stays CONFIRMED; FAIL => auto-demoted
```

`confirm_finding.sh` validates against `templates/finding.schema.json`, **independently re-runs
triage on every evidence log** and requires ≥3 to reproduce the same oracle (and same `stack_hash`
for native bugs), and enforces the class-specific rules above. Any failure rewrites
`status=UNCONFIRMED` and moves the finding to `unconfirmed/`. Then write `run.sh` and fill
`finding.md` from `templates/finding.md`.

---

## 9. Phase Severity scoring

For each confirmed finding compute a documented, pure, recomputable library-context CVSS-style
score → `$FINDINGS/findings/VH-NNNN/score.json`:

- Map `sink_class` → CWE and base impact (memory-write/RCE-class highest; DoS/abort medium;
  contract-violation by data impact).
- `score = clamp(impact × AV × AC × PR, 0, 10)` where AV/AC/PR are clamped multipliers from
  reachability (network/remote-input vs. local), trigger complexity, and required privilege.
- Bands: 9.0–10 CRITICAL, 7.0–8.9 HIGH, 4.0–6.9 MEDIUM, <4 LOW. Record the exact inputs so the
  score recomputes identically — this is part of the reproducibility record.

---

## 10. Phase Report

Write `$FINDINGS/REPORT.md` from `templates/REPORT_TEMPLATE.txt`:

1. Scope & method (target by `target_tree_sha256` only — no name/version).
2. Reproducibility (point at `ledger.jsonl` + `env_manifest.json`; run `ledger.sh verify`).
3. **Confirmed findings**, ordered by score, each with one-command repro (`findings/VH-NNNN/run.sh`).
4. Unconfirmed leads (reported as leads, explicitly **not** bugs).
5. SCA dependency exposure (component-level).
6. Black-box compliance statement (identity files seen-but-unread; no leak in any record).

**Before writing Section 3, gate every finding** — a finding that fails the proof gate must not be
published:

```bash
bash "$SKILL/scripts/confirm_finding.sh" gate-all "$FINDINGS"   # demotes any bad CONFIRMED; non-zero if any failed
```

Finally verify the record and the black-box compliance of everything that ships:

```bash
bash "$SKILL/scripts/ledger.sh" verify "$FINDINGS"                                  # chain intact
bash "$SKILL/scripts/blackbox_guard.sh" scan-file "$FINDINGS/REPORT.md"             # report: no identity leak
for b in "$FINDINGS"/blobs/*; do bash "$SKILL/scripts/blackbox_guard.sh" scan-file "$b" --strict || \
  echo "LEAK in blob $b — investigate"; done                                        # prompts/responses: strict
```

---

## Scale discipline (applies to every phase)

- Use `Glob`/`Grep` to locate surfaces; **never read the whole tree**. Rank, then sample.
- Bound every tool (`timeout`, `-max_total_time`, file caps). Tools are optional and
  non-fatal — degrade, never abort the pipeline.
- Scope incrementally (`--subtree`, `--changed-from` for *scoping only*).
- Keep raw tool output untouched in `raw/` — it is the reproducibility evidence.

## Scripts (all under `$SKILL/scripts/`, all non-fatal + ledger-logging)

- `ledger.sh` (init/append/verify, hash-chained), `blackbox_guard.sh` (+ `blackbox_denylist.txt`),
  `selftest.sh` (preflight proof of the whole loop).
- SCA: `sca_install.sh`, `sca_scan.sh`, `sca_fingerprint.sh`, `sca_normalize.py`.
- SAST: `sast_scan.sh`, `sast_merge.py`.
- DAST: `build_sanitized.sh` (instrumented real build — preferred), `build_cpp_fuzzer.sh`
  (single-unit fallback, records stub provenance), `run_atheris.sh` (verifies instrumentation),
  `triage_crash.sh` (classify + stack_hash), `new_finding.sh` (scaffold),
  **`confirm_finding.sh` (the enforced proof gate — `validate` / `gate-all`)**.

## Schemas & templates (the contracts — referenced, not duplicated)

- LLM candidate: `templates/candidate.schema.json` (poc_oracle vocab == triage evidence_type).
- Proven finding: `templates/finding.schema.json` (CONFIRMED requires poc+evidence+oracle.confirmed).
- SCA finding: schema `sca-1.0` (in `sca_normalize.py`); SAST leads: `sast-leads-1.0`.
- Reviewer prompt: `templates/reviewer_prompt.md`. Sink taxonomy: `templates/sink_taxonomy.md`.
- Harnesses: `templates/atheris_harness.py`, `templates/cpp_fuzz_harness.cc`,
  `templates/property_test.py`. Finding/report: `templates/finding.md`,
  `templates/REPORT_TEMPLATE.txt`. Worked example: `examples/oob_demo/`.

## The three rules, restated (never violate)

1. **Reproducibility:** append to `ledger.jsonl` at every step; content-address every prompt/response
   blob; temp-0; pin the model id. Tools replay deterministically; LLM steps are logged, not seeded.
2. **Black-box:** never read/say host identity or version; gate paths/git through `blackbox_guard.sh`;
   scan prompt blobs with `--strict` and the final report before shipping.
3. **Proof:** no AI-generated PoC tripping a machine-detectable oracle ⇒ `UNCONFIRMED`, never reported.
   The status is decided by `confirm_finding.sh`, not by hand.