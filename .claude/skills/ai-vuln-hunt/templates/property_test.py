#!/usr/bin/env python3
"""property_test.py — invariant / differential / metamorphic testing for numeric kernels.

The novel ML angle: instead of waiting for a segfault, assert MATHEMATICAL CONTRACTS the code
must satisfy, and let Hypothesis shrink any violation to a minimal trigger.

4 oracle families (fill the SLOTS from black-box reading of code/):
  1. no-crash robustness   — hostile inputs must not crash / hang / OOM.            -> ORACLE-VIOLATION
  2. contract / invariant  — output must satisfy a STATED invariant                 -> INVARIANT-VIOLATION
                             (shape rule, dtype rule, range bound, idempotence).
  3. differential          — target vs. an AI-written, JUSTIFIED reference impl.     -> DIFFERENTIAL-MISMATCH
  4. metamorphic           — f(transform(x)) relates predictably to f(x).           -> METAMORPHIC-VIOLATION

The violation tags above are exactly what scripts/triage_crash.sh classifies (evidence_type
invariant_violation / differential_mismatch / metamorphic_violation). Because these oracles raise
a plain AssertionError (no native frame), confirm_finding.sh gates them on a cited kernel
file:line + a recorded failing input + deterministic replay — NOT on a crash frame.

DETERMINISM (required for the >=90% reproducibility contract): we load a derandomized Hypothesis
profile with NO example database, so the discovery run is reproducible. When a counterexample is
found, FREEZE it: write the minimal failing input to a regression seed file and author a standalone
poc.py that calls the kernel on that literal input and asserts the oracle — run.sh replays poc.py
3x. The standalone PoC is deterministic by construction; Hypothesis is only the discovery engine.

DIFFERENTIAL RIGOR (avoid false positives — worse than a miss in a competition):
  * A differential test needs an explicit, human-readable INVARIANT / spec citation justifying why
    the reference is authoritative (set REFERENCE_JUSTIFICATION). An unjustified self-authored
    reference is NOT "an explicitly stated invariant".
  * Require a GENEROUS tolerance and a QUALITATIVE divergence (NaN vs finite, sign flip, orders of
    magnitude) — pure last-ULP float differences are DOWNGRADED to UNCONFIRMED leads, never bugs.
  * Prefer metamorphic / invariant oracles (which don't depend on a correct reference) for CONFIRMED.

Run:  pytest -q templates/property_test.py    (after hypothesis is installed)
      AIVH_REGRESSION=findings/.../failing_input.txt pytest -q templates/property_test.py
BLACK-BOX: the reference impl is derived from the math, not from the project's identity.
"""
import math
import os
import pytest

try:
    from hypothesis import given, settings, strategies as st, HealthCheck
except Exception:  # pragma: no cover
    pytest.skip("hypothesis not installed", allow_module_level=True)

# ---- determinism: derandomized, no example DB so runs are reproducible -------
settings.register_profile(
    "aivh", derandomize=True, database=None, deadline=None, max_examples=300,
    print_blob=True, suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("aivh")

# Where to record a minimal failing input so a standalone PoC can replay it deterministically.
REGRESSION_FILE = os.environ.get("AIVH_REGRESSION", "")


def _record_failing(kind, value):
    """Persist the failing input so it becomes the PoC seed; then signal triage via the tag."""
    if REGRESSION_FILE:
        try:
            with open(REGRESSION_FILE, "a") as fh:
                fh.write(f"{kind}\t{value!r}\n")
        except OSError:
            pass


# ---- SLOT 1: import the target op ------------------------------------------
# import target_pkg
# op = target_pkg.module.kernel_under_test
op = None
# SLOT D: cite the exact kernel under test (file:line in code/) — REQUIRED for confirm_finding.sh.
CITED_KERNEL = ""  # e.g. "code/core/kernels/segment_reduction_ops.cc:217"

# Hostile numeric strategies.
finite_floats = st.floats(allow_nan=False, allow_infinity=False,
                          width=64, min_value=-1e6, max_value=1e6)
hostile_floats = st.floats(allow_nan=True, allow_infinity=True, width=64)
# adversarial dims: include 0, negative, and overflow-prone magnitudes
hostile_dims = st.lists(st.integers(min_value=-3, max_value=1 << 40), min_size=0, max_size=6)
small_dims = st.lists(st.integers(min_value=0, max_value=8), min_size=0, max_size=5)


@pytest.mark.skipif(op is None, reason="fill SLOT 1")
@given(dims=hostile_dims)
def test_no_crash_robustness(dims):
    """Oracle 1: hostile shapes must raise a *contractual* error or succeed, never crash the
    process, hang, or trip a sanitizer. A non-contractual failure is the bug."""
    try:
        op(dims)
    except (ValueError, TypeError, OverflowError, MemoryError):
        pass  # contractual rejection is fine
    except Exception as e:  # pragma: no cover
        _record_failing("no_crash", dims)
        raise AssertionError(f"ORACLE-VIOLATION non-contractual exception kernel={CITED_KERNEL}: {e!r} input={dims}")


@pytest.mark.skipif(op is None, reason="fill SLOT 2")
@given(xs=st.lists(finite_floats, min_size=1, max_size=64))
def test_invariant(xs):
    """Oracle 2: state and check an invariant true of the operation. Prefer this for CONFIRMED —
    it depends on no reference. Example for a normalization kernel: output finite and bounded."""
    out = op(xs)  # SLOT 2: adapt call
    flat = out if isinstance(out, (list, tuple)) else [out]
    for v in flat:
        if not math.isfinite(v):
            _record_failing("invariant", xs)
            raise AssertionError(f"INVARIANT-VIOLATION non-finite output {v} kernel={CITED_KERNEL} input={xs}")


# ---- differential oracle ----------------------------------------------------
# SLOT 3: an explicit justification for why the reference is authoritative (a spec/definition).
REFERENCE_JUSTIFICATION = ""  # e.g. "L2 norm is sqrt(sum(x_i^2)) by definition (IEEE/textbook)."
DIFF_REL_TOL = 1e-3           # GENEROUS on purpose; tighter diffs are UNCONFIRMED leads.
DIFF_ABS_TOL = 1e-6


def _reference_impl(xs):
    """SLOT 3: AI-written independent reference, a clean re-derivation of the math the target
    claims to implement. Must be justified by REFERENCE_JUSTIFICATION above."""
    # e.g. for sum:  return sum(xs)
    raise NotImplementedError


def _qualitatively_different(got, ref):
    """Only a QUALITATIVE divergence counts (NaN/inf vs finite, sign flip, orders of magnitude).
    Pure small float drift is not a bug here."""
    if math.isnan(got) != math.isnan(ref) or math.isinf(got) != math.isinf(ref):
        return True
    if math.isfinite(got) and math.isfinite(ref):
        if (got > 0) != (ref > 0) and abs(got) > DIFF_ABS_TOL and abs(ref) > DIFF_ABS_TOL:
            return True
        return not math.isclose(got, ref, rel_tol=DIFF_REL_TOL, abs_tol=DIFF_ABS_TOL)
    return False


@pytest.mark.skipif(op is None, reason="fill SLOT 3")
@given(xs=st.lists(finite_floats, min_size=0, max_size=64))
def test_differential(xs):
    """Oracle 3: target must agree with the JUSTIFIED independent reference, qualitatively."""
    if not REFERENCE_JUSTIFICATION:
        pytest.skip("differential oracle requires REFERENCE_JUSTIFICATION (else findings are UNCONFIRMED leads)")
    try:
        ref = _reference_impl(xs)
    except NotImplementedError:
        pytest.skip("fill SLOT 3 reference impl")
    got = op(xs)
    if _qualitatively_different(got, ref):
        _record_failing("differential", xs)
        raise AssertionError(
            f"DIFFERENTIAL-MISMATCH target={got} reference={ref} kernel={CITED_KERNEL} "
            f"justification={REFERENCE_JUSTIFICATION!r} input={xs}")


@pytest.mark.skipif(op is None, reason="fill SLOT 4")
@given(xs=st.lists(finite_floats, min_size=1, max_size=32))
def test_metamorphic_scale(xs):
    """Oracle 4: metamorphic relation, e.g. op(k*x) == k*op(x) for a linear op. Reference-free."""
    k = 2.0
    base = op(xs)            # SLOT 4: adapt
    scaled = op([k * x for x in xs])
    if not math.isclose(scaled, k * base, rel_tol=1e-6, abs_tol=1e-6):
        _record_failing("metamorphic", xs)
        raise AssertionError(
            f"METAMORPHIC-VIOLATION op(k*x)={scaled} k*op(x)={k * base} kernel={CITED_KERNEL} input={xs}")
