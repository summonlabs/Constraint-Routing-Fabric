// Constraint Routing Fabric -- logical clock implementations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/time.hpp"

#include <chrono>

namespace crf {
namespace {

[[nodiscard]] std::uint64_t monotonic_milliseconds() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace

SteadyClock::SteadyClock() : origin_(monotonic_milliseconds()), last_(origin_) {}

std::uint64_t SteadyClock::now_ticks() {
  const std::uint64_t now = monotonic_milliseconds();
  // The clock never runs backwards, even if the platform counter were to.
  if (now > last_) {
    last_ = now;
  }
  return last_;
}

}  // namespace crf
