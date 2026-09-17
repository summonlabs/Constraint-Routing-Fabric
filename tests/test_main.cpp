// Constraint Routing Fabric -- test runner entry point.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "test_support.hpp"

int main(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else if (argument == "--list") {
      list_only = true;
    } else if (argument == "--help") {
      std::printf("usage: crf_tests [--filter=substring] [--list]\n");
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argument.c_str());
      return 2;
    }
  }

  std::vector<::crf::test::TestCase>& cases = ::crf::test::registry();
  std::stable_sort(cases.begin(), cases.end(), [](const auto& a, const auto& b) {
    if (a.suite != b.suite) return a.suite < b.suite;
    return a.name < b.name;
  });

  if (list_only) {
    for (const auto& test : cases) {
      std::printf("%s.%s\n", test.suite.c_str(), test.name.c_str());
    }
    return 0;
  }

  std::size_t executed = 0;
  std::size_t failed_before = 0;
  for (const auto& test : cases) {
    const std::string full = test.suite + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      continue;
    }
    ::crf::test::current_test() = full;
    const std::uint64_t before = ::crf::test::failure_count();
    test.body();
    ++executed;
    if (::crf::test::failure_count() != before) {
      ++failed_before;
      std::printf("FAILED %s\n", full.c_str());
    } else {
      std::printf("ok     %s\n", full.c_str());
    }
    std::fflush(stdout);
  }

  std::printf("\n%d test case(s) executed, %d failed, %llu assertion failure(s)\n",
              static_cast<int>(executed), static_cast<int>(failed_before),
              static_cast<unsigned long long>(::crf::test::failure_count()));
  if (executed == 0) {
    std::printf("no test case matched the filter\n");
    return 2;
  }
  return failed_before == 0 ? 0 : 1;
}
