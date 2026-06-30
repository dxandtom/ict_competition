# {{ID}} — {{TITLE}}

- **Status:** UNCONFIRMED  <!-- becomes CONFIRMED only after PoC + oracle evidence -->
- **Sink class:** {{SINK}}
- **Severity:** {{SEVERITY}}
- **CWE:** TBD
- **Location:** `code/<file>:<line>`

## Summary
One paragraph: what the defect is, in code terms, with no reference to project
identity or version. State the violated invariant or the memory-safety rule broken.

## Entry point and reachability
- Public API / parse boundary an external caller can reach:
- Why the tainted value flows from there to the sink (black-box reasoning):

## Taint path
1. `code/<file>:<line>` — value enters / is read
2. `code/<file>:<line>` — propagated / arithmetic that overflows or skips a check
3. `code/<file>:<line>` — **sink**: the missing bounds/validation here

## Missing check
The exact validation that should exist but does not (e.g. `dim >= 0`,
`offset + len <= buffer_size`, `axis < rank`).

## Proof of Concept
- **PoC file:** `poc.<ext>` (AI-generated; describe what it constructs)
- **Oracle:** ASAN / UBSAN / SIGSEGV / abort / invariant-violation (pick one)
- **Run:** `./run.sh`
- **Evidence:** `evidence/run1.log`, `evidence/run2.log`, `evidence/run3.log`
  (the oracle must fire deterministically across all three)

```
<paste the load-bearing lines of the sanitizer/oracle report, including the
top app frame inside code/ — this is what proves the bug is real>
```

## Severity rationale
Impact x exploitability under library context. Score: see `score.json` (recomputed by
scripts: impact x clamped AV/AC/PR -> 0-10 band).

## Notes
Anything the cross-validation panel flagged; why the red-team refutation failed.
