// Constraint Routing Fabric -- pure deterministic evaluator.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_EVALUATOR_HPP
#define CONSTRAINT_ROUTING_FABRIC_EVALUATOR_HPP

#include <cstdint>
#include <span>
#include <vector>

#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/limits.hpp"

namespace crf {

/// Everything the evaluator is allowed to look at. The evaluator performs no
/// I/O, holds no locks and consults no global state: it is a pure function of
/// this context and the candidate.
struct EvaluationContext {
  const ConstraintSet* set{nullptr};
  /// Current authoritative evidence generations.
  EvidenceRequirements current{};
  /// Generation the caller believes the set is at. When valid and different
  /// from the set generation the evaluation is reported stale.
  ConstraintSetGeneration requested_set_generation{};
  const Limits* limits{nullptr};
  std::uint64_t now_tick{0};
  Provenance provenance{};
  EvaluationGeneration generation{};
  /// Set by the coordinator once it has authorized the caller against the live
  /// authority registry. When false the evaluator applies the default-deny
  /// authority-context gate itself.
  bool authority_verified{false};
};

/// Evaluates one candidate against one constraint set. Deterministic: the same
/// inputs always produce the same outcome, primary reason, reason vector and
/// digest, independent of any container ordering.
[[nodiscard]] Result<EvaluationRecord> evaluate_candidate(const EvaluationContext& context,
                                                          const CandidatePath& candidate);

/// Evaluates a bounded candidate population and produces the deterministic
/// admissible ordering. Candidates are canonicalized by identity first, so the
/// caller's container order is never observable.
[[nodiscard]] Result<EvaluationBatch> evaluate_batch(const EvaluationContext& context,
                                                     std::span<const CandidatePath> candidates);

/// Converts a reason vector into its canonical order and applies the two
/// explanation bounds: at most ::Limits::max_failed_constraints_per_evaluation
/// distinct constraints may be represented, and at most
/// ::Limits::max_explanation_reasons reasons may be retained in total. The
/// primary reason is always the first element, so neither bound can change the
/// outcome.
void canonicalize_reasons(std::vector<Reason>& reasons, const Limits& limits);
[[nodiscard]] ReasonCode primary_reason_of(std::span<const Reason> reasons) noexcept;

/// Derives the outcome class from a reason vector. No reasons means admissible.
[[nodiscard]] Outcome outcome_from_reasons(std::span<const Reason> reasons,
                                           bool has_preferences) noexcept;

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_EVALUATOR_HPP
