#!/usr/bin/env python3
"""property_test.py — 针对数值内核的不变量 / 差分 / 蜕变测试。

新颖的 ML 思路：与其等待段错误，不如断言代码必须满足的数学契约（MATHEMATICAL CONTRACTS），
并让 Hypothesis 将任何违例收缩到最小触发条件。

4 类预言机（从对 code/ 的黑盒阅读中填充各个 SLOT）：
  1. 无崩溃健壮性     — 恶意输入不得崩溃 / 挂起 / OOM。                      -> ORACLE-VIOLATION
  2. 契约 / 不变量    — 输出必须满足某条声明的不变量（STATED invariant）       -> INVARIANT-VIOLATION
                       （形状规则、dtype 规则、范围界限、幂等性）。
  3. 差分            — 目标实现 vs. 一个 AI 编写、有据可依的参考实现。          -> DIFFERENTIAL-MISMATCH
  4. 蜕变            — f(transform(x)) 与 f(x) 之间存在可预测的关系。          -> METAMORPHIC-VIOLATION

上述违例标签正是 scripts/triage_crash.sh 所分类的内容（evidence_type
invariant_violation / differential_mismatch / metamorphic_violation）。由于这些预言机抛出的是
普通 AssertionError（没有原生栈帧），confirm_finding.sh 对它们的判定依据是被引用的内核
file:line + 一条记录在案的失败输入 + 确定性重放 —— 而不是崩溃栈帧。

确定性（>=90% 可复现契约所要求）：我们加载一个去随机化的 Hypothesis 配置，不使用样例数据库，
以便发现运行可复现。当找到反例时，将其冻结（FREEZE）：把最小失败输入写入回归种子文件，并编写一个
独立的 poc.py，在该字面量输入上调用内核并断言预言机 —— run.sh 会重放 poc.py 3 次。该独立 PoC
在构造上即是确定性的；Hypothesis 仅作为发现引擎。

差分严谨性（避免误报 —— 在竞赛中误报比漏报更糟）：
  * 差分测试需要一条显式的、人类可读的不变量 / 规范引用来论证为何参考实现是权威的
    （设置 REFERENCE_JUSTIFICATION）。一个无据可依的自撰参考实现并不算
    “一条明确声明的不变量”。
  * 要求一个宽松（GENEROUS）的容差以及一个定性（QUALITATIVE）的发散（NaN vs 有限值、符号翻转、
    数量级差异）—— 纯粹的末位 ULP 浮点差异会被降级（DOWNGRADED）为未确认线索，绝不算 bug。
  * 优先选用蜕变 / 不变量预言机（它们不依赖于一个正确的参考实现）来得到 CONFIRMED。

运行：pytest -q templates/property_test.py    （在安装 hypothesis 之后）
      AIVH_REGRESSION=findings/.../failing_input.txt pytest -q templates/property_test.py
黑盒：参考实现由数学推导而来，而非由项目的身份推导而来。
"""
import math
import os
import pytest

try:
    from hypothesis import given, settings, strategies as st, HealthCheck
except Exception:  # pragma: no cover
    pytest.skip("hypothesis not installed", allow_module_level=True)

# ---- 确定性：去随机化、不使用样例数据库，以便运行可复现 -------
settings.register_profile(
    "aivh", derandomize=True, database=None, deadline=None, max_examples=300,
    print_blob=True, suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("aivh")

# 记录最小失败输入的位置，使独立 PoC 能够确定性地重放它。
REGRESSION_FILE = os.environ.get("AIVH_REGRESSION", "")


def _record_failing(kind, value):
    """持久化失败输入，使其成为 PoC 种子；随后通过标签向 triage 发出信号。"""
    if REGRESSION_FILE:
        try:
            with open(REGRESSION_FILE, "a") as fh:
                fh.write(f"{kind}\t{value!r}\n")
        except OSError:
            pass


# ---- SLOT 1：导入目标算子 ------------------------------------------
# import target_pkg
# op = target_pkg.module.kernel_under_test
op = None
# SLOT D：引用受测的确切内核（code/ 中的 file:line）—— confirm_finding.sh 必需。
CITED_KERNEL = ""  # 例如 "code/core/kernels/segment_reduction_ops.cc:217"

# 恶意数值策略。
finite_floats = st.floats(allow_nan=False, allow_infinity=False,
                          width=64, min_value=-1e6, max_value=1e6)
hostile_floats = st.floats(allow_nan=True, allow_infinity=True, width=64)
# 对抗性维度：包含 0、负数以及易溢出的量级
hostile_dims = st.lists(st.integers(min_value=-3, max_value=1 << 40), min_size=0, max_size=6)
small_dims = st.lists(st.integers(min_value=0, max_value=8), min_size=0, max_size=5)


@pytest.mark.skipif(op is None, reason="fill SLOT 1")
@given(dims=hostile_dims)
def test_no_crash_robustness(dims):
    """预言机 1：恶意形状必须抛出*契约性*错误或成功，绝不能使进程崩溃、挂起，
    或触发 sanitizer。非契约性的失败即为 bug。"""
    try:
        op(dims)
    except (ValueError, TypeError, OverflowError, MemoryError):
        pass  # 契约性拒绝是可以接受的
    except Exception as e:  # pragma: no cover
        _record_failing("no_crash", dims)
        raise AssertionError(f"ORACLE-VIOLATION non-contractual exception kernel={CITED_KERNEL}: {e!r} input={dims}")


@pytest.mark.skipif(op is None, reason="fill SLOT 2")
@given(xs=st.lists(finite_floats, min_size=1, max_size=64))
def test_invariant(xs):
    """预言机 2：陈述并检查该操作成立的一条不变量。优先用它来得到 CONFIRMED ——
    它不依赖任何参考实现。归一化内核的示例：输出有限且有界。"""
    out = op(xs)  # SLOT 2：适配调用
    flat = out if isinstance(out, (list, tuple)) else [out]
    for v in flat:
        if not math.isfinite(v):
            _record_failing("invariant", xs)
            raise AssertionError(f"INVARIANT-VIOLATION non-finite output {v} kernel={CITED_KERNEL} input={xs}")


# ---- 差分预言机 ----------------------------------------------------
# SLOT 3：论证参考实现为何权威的显式依据（一份规范/定义）。
REFERENCE_JUSTIFICATION = ""  # 例如 "L2 norm is sqrt(sum(x_i^2)) by definition (IEEE/textbook)."
DIFF_REL_TOL = 1e-3           # 刻意宽松；更紧的差异属于未确认（UNCONFIRMED）线索。
DIFF_ABS_TOL = 1e-6


def _reference_impl(xs):
    """SLOT 3：AI 编写的独立参考实现，对目标声称要实现的数学进行干净的重新推导。
    必须由上方的 REFERENCE_JUSTIFICATION 论证。"""
    # 例如对于 sum：return sum(xs)
    raise NotImplementedError


def _qualitatively_different(got, ref):
    """只有定性（QUALITATIVE）的发散才算数（NaN/inf vs 有限值、符号翻转、数量级差异）。
    纯粹的微小浮点漂移在此不算 bug。"""
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
    """预言机 3：目标必须在定性上与有据可依的独立参考实现一致。"""
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
    """预言机 4：蜕变关系，例如对于线性算子 op(k*x) == k*op(x)。无需参考实现。"""
    k = 2.0
    base = op(xs)            # SLOT 4：适配
    scaled = op([k * x for x in xs])
    if not math.isclose(scaled, k * base, rel_tol=1e-6, abs_tol=1e-6):
        _record_failing("metamorphic", xs)
        raise AssertionError(
            f"METAMORPHIC-VIOLATION op(k*x)={scaled} k*op(x)={k * base} kernel={CITED_KERNEL} input={xs}")
