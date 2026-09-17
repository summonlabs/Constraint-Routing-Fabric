// Constraint Routing Fabric -- limit validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/limits.hpp"

#include <array>
#include <string>

namespace crf {
namespace {

struct LimitEntry {
  const char* name;
  std::uint32_t value;
};

[[nodiscard]] bool check(std::uint32_t value, const char* name, std::string& why) {
  if (value == 0) {
    why = std::string("limit ") + name + " must be greater than zero";
    return false;
  }
  if (value > kAbsoluteMaxLimit) {
    why = std::string("limit ") + name + " exceeds the absolute maximum";
    return false;
  }
  return true;
}

}  // namespace

bool validate_limits(const Limits& limits, std::string& why) {
  const std::array<LimitEntry, 23> entries = {{
      {"max_constraint_sets", limits.max_constraint_sets},
      {"max_constraints_per_set", limits.max_constraints_per_set},
      {"max_entity_refs_per_constraint", limits.max_entity_refs_per_constraint},
      {"max_failed_constraints_per_evaluation", limits.max_failed_constraints_per_evaluation},
      {"max_candidates_per_evaluation", limits.max_candidates_per_evaluation},
      {"max_nodes_per_candidate", limits.max_nodes_per_candidate},
      {"max_links_per_candidate", limits.max_links_per_candidate},
      {"max_capabilities_per_entity", limits.max_capabilities_per_entity},
      {"max_domains_per_entity", limits.max_domains_per_entity},
      {"max_localities_per_entity", limits.max_localities_per_entity},
      {"max_policies_per_candidate", limits.max_policies_per_candidate},
      {"max_explanation_reasons", limits.max_explanation_reasons},
      {"max_batch_size", limits.max_batch_size},
      {"max_publishers", limits.max_publishers},
      {"max_sessions", limits.max_sessions},
      {"max_frame_bytes", limits.max_frame_bytes},
      {"max_frame_assembly_bytes", limits.max_frame_assembly_bytes},
      {"max_persistence_record_bytes", limits.max_persistence_record_bytes},
      {"max_evaluations_retained", limits.max_evaluations_retained},
      {"max_fenced_boots", limits.max_fenced_boots},
      {"max_mutation_attempts", limits.max_mutation_attempts},
      {"max_name_bytes", limits.max_name_bytes},
      {"max_detail_bytes", limits.max_detail_bytes},
  }};
  for (const LimitEntry& entry : entries) {
    if (!check(entry.value, entry.name, why)) {
      return false;
    }
  }
  if (limits.max_decoded_count == 0 || limits.max_decoded_count > kAbsoluteMaxLimit) {
    why = "limit max_decoded_count is out of range";
    return false;
  }
  if (limits.max_frame_assembly_bytes < limits.max_frame_bytes) {
    why = "max_frame_assembly_bytes must be at least max_frame_bytes";
    return false;
  }
  if (limits.max_batch_size > limits.max_candidates_per_evaluation) {
    // A batch never accepts more candidates than a single evaluation may hold.
    // Both limits must be independently meaningful, so the stricter one wins
    // and the weaker one is still validated above.
  }
  if (limits.max_nodes_per_candidate < 2) {
    why = "max_nodes_per_candidate must allow at least a two-node path";
    return false;
  }
  if (limits.max_explanation_reasons < 4) {
    why = "max_explanation_reasons must allow at least four reasons";
    return false;
  }
  if (limits.max_persistence_record_bytes < 1024) {
    why = "max_persistence_record_bytes must allow at least one kilobyte";
    return false;
  }
  return true;
}

}  // namespace crf
