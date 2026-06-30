// cpp_fuzz_harness.cc — libFuzzer + ASAN/UBSAN harness template for a single C/C++ unit.
//
// Specialize the 3 SLOTS from black-box reading of code/:
//   SLOT 1: #include the unit's header(s) and declare the target function.
//   SLOT 2: decode the fuzzer bytes into the target's arguments (mirror the parsing
//           you observed: dims, dtype tags, counts, offsets — feed hostile values).
//   SLOT 3: call the target; let ASAN/UBSAN observe the crash. Do NOT swallow it.
//
// Build (no Bazel needed):
//   scripts/build_cpp_fuzzer.sh templates/cpp_fuzz_harness.cc out/fuzz \
//       code/path/to/unit.cc -- -Icode/include -Icode
//   # the build script auto-generates weak link stubs from undefined references.
//
// Run:
//   ASAN_OPTIONS=abort_on_error=1:halt_on_error=1 \
//   UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
//   out/fuzz -runs=200000 -max_total_time=120 corpus/
//
// BLACK-BOX: drive only by the parsing/shape logic observed in code/, never identity.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

// ---- SLOT 1: include target + declare entry --------------------------------
// #include "code/path/to/unit.h"
// extern "C" int target_compute(const int32_t* dims, size_t ndim,
//                               const uint8_t* data, size_t len);

namespace {
// Helper: pull a bounded int from the byte stream.
inline uint64_t take_u64(const uint8_t*& p, const uint8_t* end, uint64_t lo, uint64_t hi) {
  uint64_t v = 0;
  for (int i = 0; i < 8 && p < end; ++i) v = (v << 8) | *p++;
  if (hi <= lo) return lo;
  return lo + (v % (hi - lo + 1));
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;
  const uint8_t* p = data;
  const uint8_t* end = data + size;

  // ---- SLOT 2: decode hostile arguments ------------------------------------
  size_t ndim = static_cast<size_t>(take_u64(p, end, 0, 8));
  std::vector<int32_t> dims(ndim);
  for (size_t i = 0; i < ndim; ++i) {
    // include 0, huge, and overflow-prone dim values
    dims[i] = static_cast<int32_t>(take_u64(p, end, 0, 0x7fffffffULL));
  }
  size_t remaining = static_cast<size_t>(end - p);

  // ---- SLOT 3: invoke the target -------------------------------------------
  // target_compute(dims.data(), ndim, p, remaining);
  (void)remaining;
  (void)dims;
  return 0;
}
