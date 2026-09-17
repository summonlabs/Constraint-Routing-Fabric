// Constraint Routing Fabric -- deterministic logical time.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_TIME_HPP
#define CONSTRAINT_ROUTING_FABRIC_TIME_HPP

#include <cstdint>

namespace crf {

/// Logical tick source. One tick is nominally one millisecond of monotonic
/// time, but the runtime never depends on wall-clock semantics: every
/// correctness rule uses tick ordering only.
class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock() = default;

  [[nodiscard]] virtual std::uint64_t now_ticks() = 0;
};

/// Monotonic process clock. Never runs backwards.
class SteadyClock final : public Clock {
 public:
  SteadyClock();
  [[nodiscard]] std::uint64_t now_ticks() override;

 private:
  std::uint64_t origin_{0};
  std::uint64_t last_{0};
};

/// Deterministic clock for tests: time only moves when the test moves it.
/// No test in this repository uses a sleep for semantic correctness.
class ManualClock final : public Clock {
 public:
  ManualClock() = default;
  explicit ManualClock(std::uint64_t start) : now_(start) {}

  [[nodiscard]] std::uint64_t now_ticks() override { return now_; }
  void set(std::uint64_t ticks) noexcept { now_ = ticks; }
  void advance(std::uint64_t ticks) noexcept { now_ += ticks; }

 private:
  std::uint64_t now_{1};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_TIME_HPP
