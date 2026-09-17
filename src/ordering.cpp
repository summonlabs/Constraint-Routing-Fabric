// Constraint Routing Fabric -- deterministic candidate ordering.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/ordering.hpp"

#include <algorithm>

namespace crf {

const char* to_string(CandidateTiebreak tiebreak) noexcept {
  switch (tiebreak) {
    case CandidateTiebreak::PathIdAscending: return "PathIdAscending";
    case CandidateTiebreak::NodeSequenceLexicographic: return "NodeSequenceLexicographic";
  }
  return "Unknown";
}

int compare_preferences(std::span<const PreferenceSlot> a, std::span<const PreferenceSlot> b) noexcept {
  const std::size_t shared = a.size() < b.size() ? a.size() : b.size();
  for (std::size_t index = 0; index < shared; ++index) {
    if (a[index].satisfied != b[index].satisfied) {
      return a[index].satisfied ? -1 : 1;
    }
    if (a[index].margin != b[index].margin) {
      return a[index].margin > b[index].margin ? -1 : 1;
    }
    if (a[index].weight != b[index].weight) {
      return a[index].weight > b[index].weight ? -1 : 1;
    }
  }
  if (a.size() != b.size()) {
    return a.size() < b.size() ? -1 : 1;
  }
  return 0;
}

int compare_ranked(const EvaluationRecord& a, const CandidatePath& candidate_a,
                   const EvaluationRecord& b, const CandidatePath& candidate_b,
                   const RankingPolicy& policy) noexcept {
  const int preference = compare_preferences(a.preferences, b.preferences);
  if (preference != 0) {
    return preference;
  }
  if (policy.consume_planner_rank) {
    if (candidate_a.has_planner_rank != candidate_b.has_planner_rank) {
      return candidate_a.has_planner_rank ? -1 : 1;
    }
    if (candidate_a.has_planner_rank && candidate_a.planner_rank != candidate_b.planner_rank) {
      return candidate_a.planner_rank < candidate_b.planner_rank ? -1 : 1;
    }
  }
  if (policy.consume_planner_cost) {
    if (candidate_a.has_planner_cost != candidate_b.has_planner_cost) {
      return candidate_a.has_planner_cost ? -1 : 1;
    }
    if (candidate_a.has_planner_cost && candidate_a.planner_cost != candidate_b.planner_cost) {
      const bool lower_is_better = candidate_a.planner_cost < candidate_b.planner_cost;
      const bool first_wins = policy.prefer_lower_cost ? lower_is_better : !lower_is_better;
      return first_wins ? -1 : 1;
    }
  }
  if (policy.tiebreak == CandidateTiebreak::NodeSequenceLexicographic) {
    const int nodes = compare_node_sequences(candidate_a, candidate_b);
    if (nodes != 0) {
      return nodes;
    }
  }
  // The documented final tie-break is always applied, so the order is total and
  // never depends on arrival order or container iteration order.
  if (candidate_a.path != candidate_b.path) {
    return candidate_a.path < candidate_b.path ? -1 : 1;
  }
  return 0;
}

std::vector<RankedCandidate> order_admissible(std::span<const EvaluationRecord> records,
                                              std::span<const CandidatePath> candidates,
                                              const RankingPolicy& policy) {
  std::vector<RankedCandidate> admissible;
  if (records.size() != candidates.size()) {
    return admissible;
  }
  for (std::uint32_t index = 0; index < records.size(); ++index) {
    const Outcome outcome = records[index].outcome;
    if (outcome == Outcome::Admissible || outcome == Outcome::AdmissibleWithPreferences) {
      admissible.push_back(RankedCandidate{records[index].path, index});
    }
  }
  std::stable_sort(admissible.begin(), admissible.end(),
                   [&records, &candidates, &policy](const RankedCandidate& a,
                                                    const RankedCandidate& b) {
                     return compare_ranked(records[a.record_index], candidates[a.record_index],
                                           records[b.record_index], candidates[b.record_index],
                                           policy) < 0;
                   });
  return admissible;
}

void encode_ranking_policy(ByteWriter& writer, const RankingPolicy& policy) {
  writer.put_bool(policy.consume_planner_rank);
  writer.put_bool(policy.consume_planner_cost);
  writer.put_bool(policy.prefer_lower_cost);
  writer.put_u8(static_cast<std::uint8_t>(policy.expected_cost_model));
  writer.put_u8(static_cast<std::uint8_t>(policy.tiebreak));
  writer.put_u16(0);
}

bool decode_ranking_policy(ByteReader& reader, RankingPolicy& out) {
  std::uint8_t cost_model = 0;
  std::uint8_t tiebreak = 0;
  std::uint16_t padding = 0;
  if (!reader.boolean(out.consume_planner_rank) || !reader.boolean(out.consume_planner_cost) ||
      !reader.boolean(out.prefer_lower_cost) || !reader.u8(cost_model) || !reader.u8(tiebreak) ||
      !reader.u16(padding)) {
    return false;
  }
  if (cost_model > 3 || tiebreak == 0 || tiebreak > 2 || padding != 0) {
    reader.fail();
    return false;
  }
  out.expected_cost_model = static_cast<PlannerCostModel>(cost_model);
  out.tiebreak = static_cast<CandidateTiebreak>(tiebreak);
  return true;
}

void feed_digest(SemanticHasher& hasher, const RankingPolicy& policy) {
  hasher.put_bool(policy.consume_planner_rank);
  hasher.put_bool(policy.consume_planner_cost);
  hasher.put_bool(policy.prefer_lower_cost);
  hasher.put_u8(static_cast<std::uint8_t>(policy.expected_cost_model));
  hasher.put_u8(static_cast<std::uint8_t>(policy.tiebreak));
}

}  // namespace crf
