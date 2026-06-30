#!/usr/bin/env python3
"""atheris_harness.py — coverage-guided Python fuzzer template.

Specialize the 3 SLOTS below from black-box reading of code/:
  SLOT 1: import the target callable(s).
  SLOT 2: build_input(fdp) — synthesize adversarial inputs for THIS API.
  SLOT 3: EXPECTED — exceptions that are CONTRACTUAL (not findings). Keep tight.

Run via:  scripts/run_atheris.sh templates/atheris_harness.py --time 120
A crash, SystemError, RecursionError, native abort/ASAN report, or an exception
NOT in EXPECTED is a candidate finding. (Atheris re-raises so libFuzzer records it.)

BLACK-BOX: never key behavior on project name/version; drive only by the API shape
you observed in code/.
"""
import sys
import atheris

with atheris.instrument_imports():
    # ---- SLOT 1: import the target ----------------------------------------
    # e.g.  import target_pkg
    #       fn = target_pkg.module.suspicious_op
    import importlib
    _modname = __import__("os").environ.get("FUZZ_TARGET_MODULE", "")
    _fnname = __import__("os").environ.get("FUZZ_TARGET_FN", "")
    target_mod = importlib.import_module(_modname) if _modname else None
    fn = getattr(target_mod, _fnname) if (target_mod and _fnname) else None

# Contractual exceptions that are NOT bugs (tighten per API).
# ---- SLOT 3: EXPECTED ------------------------------------------------------
EXPECTED = (ValueError, TypeError, KeyError, IndexError, OverflowError, NotImplementedError)
# Anything else (SystemError, RecursionError, MemoryError-from-tiny-input,
# segfault/abort caught natively) is a finding.
FINDING_EXC = (SystemError, RecursionError)


def build_tensor_args(fdp):
    """Synthesize adversarial ML/numeric inputs: rank 0-8, zero/huge/overflow dims,
    full dtype zoo, NaN/inf, out-of-range axes. Returns a tuple of args."""
    rank = fdp.ConsumeIntInRange(0, 8)
    dims = []
    for _ in range(rank):
        choice = fdp.ConsumeIntInRange(0, 4)
        dims.append([0, 1, fdp.ConsumeIntInRange(0, 1 << 20),
                     (1 << 31) - 1, (1 << 63) - 1][choice])
    dtype = fdp.PickValueInList(["float32", "float64", "int8", "int32",
                                 "int64", "uint8", "bool", "complex64"])
    axis = fdp.ConsumeIntInRange(-12, 12)
    fill = fdp.PickValueInList([0.0, -0.0, 1.0, float("nan"),
                                float("inf"), float("-inf"), 1e308])
    return {"shape": tuple(dims), "dtype": dtype, "axis": axis, "fill": fill,
            "raw": fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))}


def build_input(fdp):
    # ---- SLOT 2: shape inputs for the chosen API ---------------------------
    return build_tensor_args(fdp)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    args = build_input(fdp)
    if fn is None:
        return
    try:
        fn(**{k: v for k, v in args.items() if k in getattr(fn, "__code__",
              type("x", (), {"co_varnames": ()})).co_varnames}) \
            if hasattr(fn, "__code__") else fn(args)
    except FINDING_EXC:
        raise  # definite finding
    except EXPECTED:
        return  # contractual
    except Exception:
        # Unexpected Python exception in code that should validate inputs -> candidate.
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
