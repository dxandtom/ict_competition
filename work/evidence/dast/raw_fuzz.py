#!/usr/bin/env python3
"""raw_fuzz.py — introspective, resume-after-crash fuzzer over the op surface (black-box).

Reasoning: op wrappers that take caller-controlled shape/index/segment/split metadata are the
prime surface. We introspect each op's OpDef, synthesize adversarial inputs by dtype/attr, and
run cases in a worker subprocess. A worker death by SIGNAL (SIGSEGV/SIGABRT/SIGFPE) — or a
"Check failed" abort — is a real defect; a caught Python exception is contractual (not a bug).
The parent resumes the worker past each crash so one abort doesn't stop the sweep.

Usage:
  raw_fuzz.py gen                 # build specs.json (op x strategy)
  raw_fuzz.py worker <start>      # internal: process specs from <start>, print 'OK <idx>'
  raw_fuzz.py drive               # parent: run workers, collect crashes
"""
import json, os, sys, subprocess, signal, re

HERE = "<REPO>/findings/raw/dast"
PY = "${AIVH_PY:-python3}"
SPECS = f"{HERE}/specs.json"
PROG = f"{HERE}/progress.txt"
CRASHES = f"{HERE}/crashes.jsonl"

# Prioritize ops whose names imply risky shape/index/segment/alloc math.
KEYWORDS = re.compile(r"(Sparse|Ragged|Segment|Gather|Scatter|Reshape|Split|Concat|Slice|Pad|"
    r"Bincount|Tensor(List|Array|Scatter)|Quantize|Dequantize|Conv|Pool|Resize|Crop|Decode|"
    r"Encode|Matrix|Cholesky|Lu|Qr|Svd|Diag|Roll|Reverse|Unique|Unpack|Pack|Tile|Range|Fill|"
    r"Empty|Bcast|Broadcast|Nth|TopK|Bucketize|Unravel|Cumsum|Cumprod|Lrn|Dilation|Erosion|"
    r"NonMaxSuppression|CTC|Edit|NGram|StringSplit|Substr|Bincount|DrawBounding|Multinomial|"
    r"ParameterizedTruncated|RandomCrop|FractionalPool|AvgPool|MaxPool|BiasAdd|SpaceToBatch|"
    r"BatchToSpace|DepthToSpace|SpaceToDepth|ExtractImagePatches|MirrorPad)")


def op_list():
    import tensorflow as tf
    ops = [n for n in dir(tf.raw_ops) if n[0].isupper()]
    pri = [n for n in ops if KEYWORDS.search(n)]
    return pri


def gen():
    import tensorflow as tf
    ops = op_list()
    specs = [{"op": n, "strat": s} for n in ops for s in range(6)]
    json.dump(specs, open(SPECS, "w"))
    print(f"generated {len(specs)} specs over {len(ops)} prioritized ops")


# ---- input synthesis (deterministic per (op, strat)) ----
def build_inputs(op_name, strat):
    import tensorflow as tf, numpy as np
    from tensorflow.python.framework import op_def_registry
    od = op_def_registry.get(op_name)
    if od is None:
        raise ValueError("no opdef")
    # adversarial shape/scalar menus keyed by strategy
    shapes = [[], [0], [1], [3], [2, 2], [1, 1, 1]][strat % 6]
    big = 2 ** 40
    int_menu = [-1, 0, big, 2 ** 31, -(2 ** 20)][strat % 5]
    shp_menu = [[-1], [0], [big, big], [-1, -1], [2 ** 31]][strat % 5]
    kwargs = {}
    # attrs
    for a in od.attr:
        if a.name in ("T",) or a.type == "type":
            continue
        t = a.type
        if t == "int":
            kwargs[a.name] = int_menu
        elif t == "float":
            kwargs[a.name] = [0.0, -1.0, 1e30][strat % 3]
        elif t == "bool":
            kwargs[a.name] = (strat % 2 == 0)
        elif t == "shape":
            kwargs[a.name] = shp_menu
        elif t == "string":
            kwargs[a.name] = ""
        elif t == "list(int)":
            kwargs[a.name] = shp_menu
    # inputs -> small tensors of an adversarial dtype
    dt = [tf.float32, tf.int32, tf.int64][strat % 3]
    for inp in od.input_arg:
        if inp.type_attr and inp.type_attr in ("Tindices", "Tidx"):
            kwargs[inp.name] = tf.constant(np.array(([big] if strat % 2 else [-1]), dtype=np.int64), dtype=tf.int64)
        elif "indices" in inp.name.lower() or inp.name.lower() in ("shape", "size", "dims", "num_segments"):
            kwargs[inp.name] = tf.constant(np.array(shp_menu, dtype=np.int64))
        else:
            try:
                kwargs[inp.name] = tf.zeros(shapes, dtype=dt)
            except Exception:
                kwargs[inp.name] = tf.zeros([1], dtype=dt)
    return kwargs


def worker(start):
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    import tensorflow as tf
    specs = json.load(open(SPECS))
    prog = open(PROG, "a", buffering=1)
    for idx in range(start, len(specs)):
        op, strat = specs[idx]["op"], specs[idx]["strat"]
        try:
            kwargs = build_inputs(op, strat)
            getattr(tf.raw_ops, op)(**kwargs)
        except BaseException:
            pass  # Python-level exception is contractual
        prog.write(f"{idx}\n"); prog.flush()
    print("WORKER_DONE")


def drive():
    specs = json.load(open(SPECS))
    N = len(specs)
    open(PROG, "w").close(); open(CRASHES, "w").close()
    cur = 0; crashes = []
    while cur < N:
        log = f"{HERE}/worker_{cur}.log"
        with open(log, "w") as lf:
            p = subprocess.run([PY, __file__, "worker", str(cur)], stdout=lf,
                               stderr=subprocess.STDOUT, timeout=3600)
        done = [int(x) for x in open(PROG).read().split()] if os.path.exists(PROG) else []
        last = max(done) if done else cur - 1
        if p.returncode == 0 and "WORKER_DONE" in open(log).read():
            break
        crash_idx = last + 1
        if p.returncode < 0 and crash_idx < N:
            sig = signal.Signals(-p.returncode).name
            spec = specs[crash_idx]
            rec = {"idx": crash_idx, "op": spec["op"], "strat": spec["strat"], "signal": sig}
            crashes.append(rec)
            open(CRASHES, "a").write(json.dumps(rec) + "\n")
            print(f"CRASH idx={crash_idx} op={spec['op']} strat={spec['strat']} {sig}", flush=True)
            cur = crash_idx + 1
        else:
            # non-signal exit without finishing (rare) — advance past last
            cur = last + 2
    # dedup by op+signal
    seen = {}
    for c in crashes:
        seen[(c["op"], c["signal"])] = c
    print(f"\n=== {len(seen)} distinct crashing op(s) ===")
    for (op, sig), c in seen.items():
        print(f"  {op}  {sig}  (strat {c['strat']})")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "drive"
    if cmd == "gen": gen()
    elif cmd == "worker": worker(int(sys.argv[2]))
    else: drive()
