// Constraint Routing Fabric -- constraint-set lifecycle.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_LIFECYCLE_HPP
#define CONSTRAINT_ROUTING_FABRIC_LIFECYCLE_HPP

#include <cstdint>

namespace crf {

/// Lifecycle of a constraint set definition. Only Active yields admissibility;
/// every other state is reported explicitly and never silently ignored.
enum class ConstraintSetState : std::uint8_t {
  Declared = 1,
  Active = 2,
  Suspended = 3,
  RevalidationRequired = 4,
  Revoked = 5,
  Superseded = 6,
  Retired = 7,
};

/// Events that drive the lifecycle. Every (state, event) pair is defined and
/// tested, including the rejected pairs.
enum class LifecycleEvent : std::uint8_t {
  Activate = 1,
  Suspend = 2,
  Resume = 3,
  RequireRevalidation = 4,
  Revalidated = 5,
  Revoke = 6,
  Supersede = 7,
  Retire = 8,
  Reinstate = 9,
};

/// Result of applying an event. A rejected transition changes nothing.
struct TransitionOutcome {
  bool accepted = false;
  ConstraintSetState next = ConstraintSetState::Declared;
  /// Populated when the transition is rejected; names the deterministic reason.
  const char* rejection = "";
};

/// Pure transition function. Deterministic for every (state, event) pair.
[[nodiscard]] TransitionOutcome apply_lifecycle_event(ConstraintSetState state, LifecycleEvent event) noexcept;

[[nodiscard]] const char* to_string(ConstraintSetState state) noexcept;
[[nodiscard]] const char* to_string(LifecycleEvent event) noexcept;

/// True when the state permits an admissible outcome to be published.
[[nodiscard]] constexpr bool admits_admissibility(ConstraintSetState state) noexcept {
  return state == ConstraintSetState::Active;
}

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_LIFECYCLE_HPP
