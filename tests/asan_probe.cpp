// Constraint Routing Fabric -- AddressSanitizer instrumentation probe.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This is not a test of the library. It is a deliberate, disposable defect used
// to prove that the sanitizer instrumentation is actually active: under
// AddressSanitizer it must abort with a report, and without instrumentation it
// is undefined behaviour and must never be run.
//
//   crf_asan_probe          -> deliberate one-byte heap overflow (must abort)
//   crf_asan_probe --safe   -> the same allocation, written in bounds (must exit 0)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
  bool safe = false;
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--safe") {
      safe = true;
    }
  }
  constexpr std::size_t kBytes = 16;
  char* buffer = static_cast<char*>(std::malloc(kBytes));
  if (buffer == nullptr) {
    std::fprintf(stderr, "allocation failed\n");
    return 2;
  }
  std::memset(buffer, 0x41, kBytes);
  // One byte past the end of the allocation.
  const std::size_t offset = safe ? kBytes - 1 : kBytes;
  buffer[offset] = static_cast<char>(0x42);
  std::printf("wrote offset %zu of %zu (%s)\n", offset, kBytes, safe ? "safe" : "overflow");
  std::free(buffer);
  return 0;
}
