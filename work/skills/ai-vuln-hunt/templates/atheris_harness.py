#!/usr/bin/env python3
"""atheris_harness.py — 覆盖率引导的 Python 模糊测试模板。

通过对 code/ 的黑盒阅读，定制下面 3 个 SLOT：
  SLOT 1：导入目标可调用对象。
  SLOT 2：build_input(fdp) —— 为本 API 合成对抗性输入。
  SLOT 3：EXPECTED —— 属于契约约定（不算发现）的异常。保持范围收紧。

运行方式：  scripts/run_atheris.sh templates/atheris_harness.py --time 120
崩溃、SystemError、RecursionError、原生 abort/ASAN 报告，或不在 EXPECTED
中的异常，都是候选发现。（Atheris 会重新抛出，以便 libFuzzer 记录。）

黑盒：绝不要根据项目名称/版本来决定行为；只依据你在 code/ 中
观察到的 API 形态来驱动。
"""
import sys
import atheris

with atheris.instrument_imports():
    # ---- SLOT 1：导入目标 ----------------------------------------
    # 例如  import target_pkg
    #       fn = target_pkg.module.suspicious_op
    import importlib
    _modname = __import__("os").environ.get("FUZZ_TARGET_MODULE", "")
    _fnname = __import__("os").environ.get("FUZZ_TARGET_FN", "")
    target_mod = importlib.import_module(_modname) if _modname else None
    fn = getattr(target_mod, _fnname) if (target_mod and _fnname) else None

# 属于契约约定、并非缺陷的异常（按 API 收紧）。
# ---- SLOT 3：EXPECTED ------------------------------------------------------
EXPECTED = (ValueError, TypeError, KeyError, IndexError, OverflowError, NotImplementedError)
# 其他任何情况（SystemError、RecursionError、由极小输入引发的 MemoryError、
# 原生捕获的 segfault/abort）都算一个发现。
FINDING_EXC = (SystemError, RecursionError)


def build_tensor_args(fdp):
    """合成对抗性的 ML/数值输入：秩 0-8、零/超大/溢出维度、
    全套 dtype、NaN/inf、越界 axis。返回一个参数元组。"""
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
    # ---- SLOT 2：为所选 API 构造输入 ---------------------------
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
        raise  # 确定的发现
    except EXPECTED:
        return  # 契约约定
    except Exception:
        # 在本应校验输入的代码中出现意外的 Python 异常 -> 候选发现。
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
