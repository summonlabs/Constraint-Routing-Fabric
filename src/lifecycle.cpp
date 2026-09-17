// Constraint Routing Fabric -- lifecycle transition table.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/lifecycle.hpp"

namespace crf {
namespace {

[[nodiscard]] TransitionOutcome accept(ConstraintSetState next) noexcept {
  TransitionOutcome outcome;
  outcome.accepted = true;
  outcome.next = next;
  return outcome;
}

[[nodiscard]] TransitionOutcome reject(const char* reason) noexcept {
  TransitionOutcome outcome;
  outcome.accepted = false;
  outcome.rejection = reason;
  return outcome;
}

}  // namespace

TransitionOutcome apply_lifecycle_event(ConstraintSetState state, LifecycleEvent event) noexcept {
  switch (state) {
    case ConstraintSetState::Declared:
      switch (event) {
        case LifecycleEvent::Activate: return accept(ConstraintSetState::Active);
        case LifecycleEvent::Revoke: return accept(ConstraintSetState::Revoked);
        case LifecycleEvent::Supersede: return accept(ConstraintSetState::Superseded);
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        default: return reject("declared set accepts only Activate, Revoke, Supersede or Retire");
      }
    case ConstraintSetState::Active:
      switch (event) {
        case LifecycleEvent::Suspend: return accept(ConstraintSetState::Suspended);
        case LifecycleEvent::RequireRevalidation: return accept(ConstraintSetState::RevalidationRequired);
        case LifecycleEvent::Revoke: return accept(ConstraintSetState::Revoked);
        case LifecycleEvent::Supersede: return accept(ConstraintSetState::Superseded);
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        default: return reject("active set accepts only Suspend, RequireRevalidation, Revoke, Supersede or Retire");
      }
    case ConstraintSetState::Suspended:
      switch (event) {
        case LifecycleEvent::Resume: return accept(ConstraintSetState::Active);
        case LifecycleEvent::RequireRevalidation: return accept(ConstraintSetState::RevalidationRequired);
        case LifecycleEvent::Revoke: return accept(ConstraintSetState::Revoked);
        case LifecycleEvent::Supersede: return accept(ConstraintSetState::Superseded);
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        default: return reject("suspended set accepts only Resume, RequireRevalidation, Revoke, Supersede or Retire");
      }
    case ConstraintSetState::RevalidationRequired:
      switch (event) {
        case LifecycleEvent::Revalidated: return accept(ConstraintSetState::Active);
        case LifecycleEvent::Suspend: return accept(ConstraintSetState::Suspended);
        case LifecycleEvent::Revoke: return accept(ConstraintSetState::Revoked);
        case LifecycleEvent::Supersede: return accept(ConstraintSetState::Superseded);
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        default:
          return reject("revalidation-required set accepts only Revalidated, Suspend, Revoke, Supersede or Retire");
      }
    case ConstraintSetState::Revoked:
      switch (event) {
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        case LifecycleEvent::Supersede: return accept(ConstraintSetState::Superseded);
        // Reinstatement never restores admissibility directly: a reinstated set
        // must be revalidated before it can publish an admissible outcome.
        case LifecycleEvent::Reinstate: return accept(ConstraintSetState::RevalidationRequired);
        default: return reject("revoked set accepts only Reinstate, Supersede or Retire");
      }
    case ConstraintSetState::Superseded:
      switch (event) {
        case LifecycleEvent::Retire: return accept(ConstraintSetState::Retired);
        default: return reject("superseded set accepts only Retire");
      }
    case ConstraintSetState::Retired:
      return reject("retired set is terminal");
  }
  return reject("unknown lifecycle state");
}

const char* to_string(ConstraintSetState state) noexcept {
  switch (state) {
    case ConstraintSetState::Declared: return "Declared";
    case ConstraintSetState::Active: return "Active";
    case ConstraintSetState::Suspended: return "Suspended";
    case ConstraintSetState::RevalidationRequired: return "RevalidationRequired";
    case ConstraintSetState::Revoked: return "Revoked";
    case ConstraintSetState::Superseded: return "Superseded";
    case ConstraintSetState::Retired: return "Retired";
  }
  return "Unknown";
}

const char* to_string(LifecycleEvent event) noexcept {
  switch (event) {
    case LifecycleEvent::Activate: return "Activate";
    case LifecycleEvent::Suspend: return "Suspend";
    case LifecycleEvent::Resume: return "Resume";
    case LifecycleEvent::RequireRevalidation: return "RequireRevalidation";
    case LifecycleEvent::Revalidated: return "Revalidated";
    case LifecycleEvent::Revoke: return "Revoke";
    case LifecycleEvent::Supersede: return "Supersede";
    case LifecycleEvent::Retire: return "Retire";
    case LifecycleEvent::Reinstate: return "Reinstate";
  }
  return "Unknown";
}

}  // namespace crf
