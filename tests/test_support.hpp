// Constraint Routing Fabric -- minimal deterministic test framework.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// No test in this repository uses a timeout, a sleep for semantic correctness,
// or a non-deterministic input. A hanging test is a defect.
#ifndef CONSTRAINT_ROUTING_FABRIC_TEST_SUPPORT_HPP
#define CONSTRAINT_ROUTING_FABRIC_TEST_SUPPORT_HPP

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf::test {

struct TestCase {
  std::string suite{};
  std::string name{};
  std::function<void()> body{};
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

inline std::uint64_t& failure_count() {
  static std::uint64_t failures = 0;
  return failures;
}

inline std::string& current_test() {
  static std::string name;
  return name;
}

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> body) {
    registry().push_back(TestCase{suite, name, std::move(body)});
  }
};

inline void report_failure(const char* file, int line, const std::string& message) {
  ++failure_count();
  std::fprintf(stderr, "FAIL %s :: %s:%d: %s\n", current_test().c_str(), file, line, message.c_str());
}

inline void check_true(bool condition, const char* file, int line, const char* expression) {
  if (!condition) {
    report_failure(file, line, std::string("expected true: ") + expression);
  }
}

template <class T, class = void>
struct is_streamable : std::false_type {};

template <class T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

/// Deterministic rendering of a value for failure messages. Scoped enumerations
/// and identity types have no stream operator, so they are rendered by value.
template <class T>
std::string to_debug(const T& value) {
  using U = std::remove_cvref_t<T>;
  std::ostringstream stream;
  if constexpr (std::is_same_v<U, Digest256>) {
    return value.to_hex();
  } else if constexpr (std::is_enum_v<U>) {
    stream << static_cast<long long>(static_cast<std::underlying_type_t<U>>(value));
    return stream.str();
  } else if constexpr (is_streamable<U>::value) {
    stream << value;
    return stream.str();
  } else if constexpr (requires(const U& candidate) { candidate.value(); }) {
    stream << value.value();
    return stream.str();
  } else {
    return "<value>";
  }
}

template <class A, class B>
void check_eq(const A& actual, const B& expected, const char* file, int line, const char* expression) {
  if (!(actual == expected)) {
    std::ostringstream stream;
    stream << "expected " << expression << " (actual=" << to_debug(actual)
           << ", expected=" << to_debug(expected) << ")";
    report_failure(file, line, stream.str());
  }
}

inline void check_status(const Status& status, const char* file, int line, const char* expression) {
  if (!status.ok()) {
    report_failure(file, line,
                   std::string("expected success from ") + expression + ": " +
                       crf::to_string(status.code()) + " (" + status.detail() + ")");
  }
}

template <class T>
void check_result(const Result<T>& result, const char* file, int line, const char* expression) {
  if (!result.ok()) {
    report_failure(file, line,
                   std::string("expected success from ") + expression + ": " +
                       crf::to_string(result.code()) + " (" + result.detail() + ")");
  }
}

inline void check_code(const Status& status, ErrorCode expected, const char* file, int line,
                       const char* expression) {
  if (status.code() != expected) {
    report_failure(file, line, std::string("expected ") + expression + " to fail with " +
                                   crf::to_string(expected) + " but it reported " +
                                   crf::to_string(status.code()));
  }
}

template <class T>
void check_code(const Result<T>& result, ErrorCode expected, const char* file, int line,
                const char* expression) {
  if (result.code() != expected) {
    report_failure(file, line, std::string("expected ") + expression + " to fail with " +
                                   crf::to_string(expected) + " but it reported " +
                                   crf::to_string(result.code()));
  }
}

/// Deterministic pseudo-random generator. Every property test prints the seed
/// it used, and a failure always names the seed that reproduces it.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9e3779b97f4a7c15ull : seed) {}

  [[nodiscard]] std::uint64_t next() {
    state_ += 0x9e3779b97f4a7c15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
  }

  [[nodiscard]] std::uint32_t below(std::uint32_t bound) {
    return bound == 0 ? 0 : static_cast<std::uint32_t>(next() % bound);
  }

  [[nodiscard]] bool coin() { return (next() & 1u) != 0u; }

  [[nodiscard]] std::uint64_t seed() const { return seed_; }

 private:
  std::uint64_t state_{};
  std::uint64_t seed_{};
};

[[nodiscard]] inline std::string seed_message(const char* label, std::uint64_t seed) {
  std::ostringstream stream;
  stream << label << " reproduced with seed " << seed;
  return stream.str();
}

}  // namespace crf::test

#define CRF_TEST(suite_name, case_name)                                                     \
  static void crf_test_##suite_name##_##case_name##_body();                                 \
  static const ::crf::test::Registrar crf_test_##suite_name##_##case_name##_registrar(      \
      #suite_name, #case_name, crf_test_##suite_name##_##case_name##_body);                 \
  static void crf_test_##suite_name##_##case_name##_body()

#define CRF_CHECK(expression) ::crf::test::check_true((expression), __FILE__, __LINE__, #expression)
#define CRF_CHECK_EQ(actual, expected) \
  ::crf::test::check_eq((actual), (expected), __FILE__, __LINE__, #actual " == " #expected)
#define CRF_CHECK_STATUS(expression) \
  ::crf::test::check_status((expression), __FILE__, __LINE__, #expression)
#define CRF_CHECK_RESULT(expression) \
  ::crf::test::check_result((expression), __FILE__, __LINE__, #expression)
/// Asserts that an operation failed with one exact error code.
#define CRF_EXPECT_CODE(expression, expected_code) \
  ::crf::test::check_code((expression), (expected_code), __FILE__, __LINE__, #expression)
#define CRF_FAIL(message) ::crf::test::report_failure(__FILE__, __LINE__, (message))

#endif  // CONSTRAINT_ROUTING_FABRIC_TEST_SUPPORT_HPP
