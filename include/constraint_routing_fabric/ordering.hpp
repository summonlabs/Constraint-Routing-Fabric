// Constraint Routing Fabric -- deterministic candidate ordering.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_ORDERING_HPP
#define CONSTRAINT_ROUTING_FABRIC_ORDERING_HPP

#include <cstdint>
#include <span>
#include <vector>

#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/evaluation.hpp"

namespace crf {

/// Documented final tie-break. Path identity is signed and stable; the node
/// sequence variant exists for callers that order by traversal shape. Arrival
/// order, container iteration order and opaque hashes are never used.
enum class CandidateTiebreak : std::uint8_t {
  PathIdAscending = 1,
  NodeSequenceLexicographic = 2,
};

/// Explicit ordering policy. Planner rank and planner cost are consumed only
/// when the operator asks for them.
struct RankingPolicy {
  bool consume_planner_rank{false};
  bool consume_planner_cost{false};
  /// When true a lower planner cost ranks first; when false a higher cost ranks
  /// first. Only consulted when ::consume_planner_cost is set.
  bool prefer_lower_cost{true};
  /// Required cost model when planner cost is consumed. A candidate whose cost
  /// model differs is reported as unknown evidence rather than silently mixed.
  PlannerCostModel expected_cost_model{PlannerCostModel::None};
  CandidateTiebreak tiebreak{CandidateTiebreak::PathIdAscending};

  friend bool operator==(const RankingPolicy& a, const RankingPolicy& b) noexcept {
    return a.consume_planner_rank == b.consume_planner_rank &&
           a.consume_planner_cost == b.consume_planner_cost &&
           a.prefer_lower_cost == b.prefer_lower_cost &&
           a.expected_cost_model == b.expected_cost_model && a.tiebreak == b.tiebreak;
  }
};

/// Deterministic relation between two admissible evaluation records, resolved
/// against the candidates they were produced from.
[[nodiscard]] int compare_ranked(const EvaluationRecord& a,
                                 const CandidatePath& candidate_a,
                                 const EvaluationRecord& b,
                                 const CandidatePath& candidate_b,
                                 const RankingPolicy& policy) noexcept;

/// Orders the admissible records of a batch. \p records and \p candidates are
/// parallel arrays. Not-admissible records are returned in canonical PathId
/// order. The sort is stable and total: equal keys never depend on input order.
[[nodiscard]] std::vector<RankedCandidate> order_admissible(std::span<const EvaluationRecord> records,
                                                            std::span<const CandidatePath> candidates,
                                                            const RankingPolicy& policy);

/// Lexicographic comparison of preference vectors. Returns <0 when \p a ranks
/// strictly before \p b.
[[nodiscard]] int compare_preferences(std::span<const PreferenceSlot> a,
                                      std::span<const PreferenceSlot> b) noexcept;

void encode_ranking_policy(ByteWriter& writer, const RankingPolicy& policy);
[[nodiscard]] bool decode_ranking_policy(ByteReader& reader, RankingPolicy& out);
void feed_digest(SemanticHasher& hasher, const RankingPolicy& policy);
[[nodiscard]] const char* to_string(CandidateTiebreak tiebreak) noexcept;

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_ORDERING_HPP
