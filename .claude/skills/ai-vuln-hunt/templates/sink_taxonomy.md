# Sink Taxonomy (tuned for native numeric / ML libraries)

Each class: what it is, CWE, grep/semgrep seeds to locate candidate sites, and the PoC
oracle that proves it. Sink-class names match `candidate.schema.json` and `sast_merge.py`.

## A. Memory-safety / numeric-core (highest priority for native ML kernels)

| sink_class | CWE | grep / semgrep seeds | PoC oracle |
|------------|-----|----------------------|------------|
| `oob_rw` | CWE-787/125 | `\[[a-z_]*idx`, `memcpy`, `memmove`, `\bat(\b`, `data()\s*\+`, `reshape`, `gather`, `scatter`, `stride` | ASAN heap/stack-buffer-overflow |
| `int_overflow` | CWE-190 | `\*\s*sizeof`, `num\w*\s*\*\s*`, `+ 1\b` on sizes, `int .*= .*\*`, dim products | UBSAN signed-integer-overflow / wrong size -> ASAN |
| `narrowing_sign` | CWE-197/195 | `(int)`, `static_cast<int>`, `size_t`->`int`, `int32` from `int64` dim | UBSAN / OOB via negative-as-huge |
| `use_after_free` | CWE-416 | `free(`, `delete `, `.reset(`, `std::move`, returned-pointer-to-local | ASAN heap-use-after-free |
| `uninit` | CWE-457 | `malloc(` without init, `resize(` then read, `[[maybe_unused]]` | MSAN use-of-uninitialized |
| `availability` (native) | CWE-369/617 | `/ 0`, `% `, `CHECK(`, `assert(`, recursion on input depth | SIGFPE / CHECK-failed / abort |

## B. Deserialization / proto / archive

| sink_class | CWE | seeds | PoC oracle |
|------------|-----|-------|------------|
| `deser` | CWE-502 | `pickle.load`, `marshal.loads`, `yaml.load(` (no SafeLoader), `__reduce__`, `torch.load` | arbitrary-code / uncaught_exception / abort |
| `proto_graph` | CWE-20 | `ParseFromString`, graph/node loaders, attr maps, recursive proto | crash / invariant-violation on malformed graph |
| `path_traversal` | CWE-22 | `tarfile.extract`, `zipfile.extract`, `os.path.join(.., name)` | file written outside dir (oracle: path escape) |

## C. Injection

| sink_class | CWE | seeds | PoC oracle |
|------------|-----|-------|------------|
| `injection` | CWE-78/77 | `os.system`, `subprocess(..., shell=True)`, `eval(`, `exec(`, format-string `%n` | command executed / uncaught_exception |
| `ssrf` | CWE-918 | `requests.get(url`, `urlopen(`, user-controlled host | request to attacker host (network oracle) |

## D. Numeric-contract (the novel ML angle — property/differential testing)

| sink_class | CWE | how to find | PoC oracle |
|------------|-----|-------------|------------|
| `contract` | CWE-682/697 | math kernels (norm, softmax, conv, reduce): compare to AI reference | DIFFERENTIAL-MISMATCH / INVARIANT-VIOLATION |

## Triage weighting
A-class memory-safety and B-class deserialization rank highest (direct, provable RCE-class
impact). `weak_crypto` and style nits sink to the bottom. Always prefer a candidate with a
reachable entry point and a literal-valued trigger hypothesis.
