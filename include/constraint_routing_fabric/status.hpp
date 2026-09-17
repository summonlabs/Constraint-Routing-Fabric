// Constraint Routing Fabric -- status and result plumbing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_STATUS_HPP
#define CONSTRAINT_ROUTING_FABRIC_STATUS_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace crf {

/// Coarse failure domain of an API call. Product outcomes (admissibility and
/// friends) are modelled by ::crf::Outcome, never by a boolean.
enum class ErrorCode : std::uint32_t {
  Ok = 0,
  InvalidArgument = 1,
  Malformed = 2,
  ResourceLimit = 3,
  ContradictoryConstraintSet = 4,
  DuplicateIdentity = 5,
  UnknownConstraintKind = 6,
  InvalidNumericBound = 7,
  ImpossibleGeneration = 8,
  NotFound = 9,
  Unauthorized = 10,
  Fenced = 11,
  EpochMismatch = 12,
  StaleGeneration = 13,
  IdempotentReplay = 14,
  MutationAttemptConflict = 15,
  PersistenceUnavailable = 16,
  PersistenceCorrupt = 17,
  DurableWriteFailed = 18,
  IntegrityMismatch = 19,
  UnsupportedVersion = 20,
  Truncated = 21,
  TrailingBytes = 22,
  TransportFailure = 23,
  ProtocolViolation = 24,
  NotSupported = 25,
  Internal = 26,
};

[[nodiscard]] const char* to_string(ErrorCode code);

/// Human-readable, bounded failure detail. Detail text never participates in a
/// semantic digest.
class Error {
 public:
  Error() = default;
  Error(ErrorCode code, std::string detail) : code_(code), detail_(std::move(detail)) {}

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

 private:
  ErrorCode code_{ErrorCode::Ok};
  std::string detail_{};
};

/// Status of an operation with no payload value.
class Status {
 public:
  Status() noexcept = default;
  explicit Status(Error error) : error_(std::move(error)) {}

  [[nodiscard]] static Status success() noexcept { return Status(); }
  [[nodiscard]] static Status failure(ErrorCode code, std::string detail) {
    return Status(Error(code, std::move(detail)));
  }

  [[nodiscard]] bool ok() const noexcept { return error_.code() == ErrorCode::Ok; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code(); }
  [[nodiscard]] const std::string& detail() const noexcept { return error_.detail(); }
  [[nodiscard]] const Error& error() const noexcept { return error_; }

 private:
  Error error_{};
};

/// Result of an operation that produces a value.
template <class T>
class Result {
 public:
  Result(T value) : storage_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Error error) : storage_(std::move(error)) {}      // NOLINT(google-explicit-constructor)

  [[nodiscard]] static Result success(T value) { return Result(std::move(value)); }
  [[nodiscard]] static Result failure(ErrorCode code, std::string detail) {
    return Result(Error(code, std::move(detail)));
  }

  [[nodiscard]] bool ok() const noexcept { return std::holds_alternative<T>(storage_); }
  [[nodiscard]] ErrorCode code() const noexcept {
    return ok() ? ErrorCode::Ok : std::get<Error>(storage_).code();
  }
  [[nodiscard]] const std::string& detail() const noexcept {
    static const std::string empty{};
    return ok() ? empty : std::get<Error>(storage_).detail();
  }
  [[nodiscard]] const Error& error() const noexcept { return std::get<Error>(storage_); }

  /// Precondition: ok(). Calling value() on a failure is a programming error.
  [[nodiscard]] T& value() noexcept { return std::get<T>(storage_); }
  [[nodiscard]] const T& value() const noexcept { return std::get<T>(storage_); }

 private:
  std::variant<T, Error> storage_;
};

[[nodiscard]] inline Status to_status(const Status& status) { return status; }

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_STATUS_HPP
