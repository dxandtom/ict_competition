# 汇聚点分类（针对原生数值 / ML 库进行了调优）

每个类别包含：它是什么、CWE、用于定位候选位点的 grep/semgrep 种子，以及证明它的 PoC
验证准则（oracle）。汇聚点类别名称与 `candidate.schema.json` 和 `sast_merge.py` 保持一致。

## A. 内存安全 / 数值核心（原生 ML 内核的最高优先级）

| sink_class | CWE | grep / semgrep seeds | PoC oracle |
|------------|-----|----------------------|------------|
| `oob_rw` | CWE-787/125 | `\[[a-z_]*idx`, `memcpy`, `memmove`, `\bat(\b`, `data()\s*\+`, `reshape`, `gather`, `scatter`, `stride` | ASAN 堆/栈缓冲区溢出 |
| `int_overflow` | CWE-190 | `\*\s*sizeof`, `num\w*\s*\*\s*`, 尺寸上的 `+ 1\b`, `int .*= .*\*`, 维度乘积 | UBSAN 有符号整数溢出 / 错误尺寸 -> ASAN |
| `narrowing_sign` | CWE-197/195 | `(int)`, `static_cast<int>`, `size_t`->`int`, 由 `int64` 维度得到的 `int32` | UBSAN / 因负数被当作巨大值导致 OOB |
| `use_after_free` | CWE-416 | `free(`, `delete `, `.reset(`, `std::move`, 返回指向局部变量的指针 | ASAN 堆释放后使用 |
| `uninit` | CWE-457 | 未初始化的 `malloc(`、`resize(` 后读取、`[[maybe_unused]]` | MSAN 使用未初始化值 |
| `availability` (native) | CWE-369/617 | `/ 0`, `% `, `CHECK(`, `assert(`, 基于输入深度的递归 | SIGFPE / CHECK 失败 / abort |

## B. 反序列化 / proto / 归档

| sink_class | CWE | seeds | PoC oracle |
|------------|-----|-------|------------|
| `deser` | CWE-502 | `pickle.load`, `marshal.loads`, `yaml.load(`（无 SafeLoader）, `__reduce__`, `torch.load` | 任意代码执行 / 未捕获异常 / abort |
| `proto_graph` | CWE-20 | `ParseFromString`、图/节点加载器、属性映射、递归 proto | 畸形图导致崩溃 / 不变式违反 |
| `path_traversal` | CWE-22 | `tarfile.extract`, `zipfile.extract`, `os.path.join(.., name)` | 文件被写到目录之外（oracle：路径逃逸） |

## C. 注入

| sink_class | CWE | seeds | PoC oracle |
|------------|-----|-------|------------|
| `injection` | CWE-78/77 | `os.system`, `subprocess(..., shell=True)`, `eval(`, `exec(`, 格式化字符串 `%n` | 命令被执行 / 未捕获异常 |
| `ssrf` | CWE-918 | `requests.get(url`, `urlopen(`, 用户可控的主机 | 向攻击者主机发起请求（网络 oracle） |

## D. 数值契约（新颖的 ML 视角 —— 属性测试 / 差分测试）

| sink_class | CWE | how to find | PoC oracle |
|------------|-----|-------------|------------|
| `contract` | CWE-682/697 | 数学内核（norm、softmax、conv、reduce）：与 AI 参考实现对比 | DIFFERENTIAL-MISMATCH / INVARIANT-VIOLATION |

## 分诊权重
A 类内存安全和 B 类反序列化排名最高（具有直接、可证明的 RCE 级影响）。`weak_crypto`
和风格瑕疵沉到最底部。始终优先选择具有可达入口点且带有字面量取值触发假设的候选项。
