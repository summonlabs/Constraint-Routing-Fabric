// Constraint Routing Fabric -- explicit, bounded resource limits.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_LIMITS_HPP
#define CONSTRAINT_ROUTING_FABRIC_LIMITS_HPP

#include <cstdint>
#include <string>

namespace crf {

/// Every bound the runtime enforces. A limit that is not enforced by a test is a defect.
/// Limits are part of the evaluation input so that a caller can tighten them per request.
struct Limits {
  // --- constraint definitions -------------------------------------------------
  std::uint32_t max_constraint_sets = 64;
  std::uint32_t max_constraints_per_set = 256;
  std::uint32_t max_entity_refs_per_constraint = 16;
  std::uint32_t max_failed_constraints_per_evaluation = 256;

  // --- candidates and evidence ------------------------------------------------
  std::uint32_t max_candidates_per_evaluation = 64;
  std::uint32_t max_nodes_per_candidate = 64;
  std::uint32_t max_links_per_candidate = 64;
  std::uint32_t max_capabilities_per_entity = 32;
  std::uint32_t max_domains_per_entity = 16;
  std::uint32_t max_localities_per_entity = 8;
  std::uint32_t max_policies_per_candidate = 32;

  // --- explanations -----------------------------------------------------------
  std::uint32_t max_explanation_reasons = 64;

  // --- distributed ------------------------------------------------------------
  std::uint32_t max_batch_size = 64;
  std::uint32_t max_publishers = 32;
  std::uint32_t max_sessions = 32;
  std::uint32_t max_frame_bytes = 1u << 20;         // 1 MiB per frame
  std::uint32_t max_frame_assembly_bytes = 1u << 22;  // 4 MiB across started frames

  // --- persistence ------------------------------------------------------------
  std::uint32_t max_persistence_record_bytes = 1u << 24;  // 16 MiB envelope
  std::uint32_t max_evaluations_retained = 1024;
  std::uint32_t max_fenced_boots = 256;
  std::uint32_t max_mutation_attempts = 256;

  // --- naming -----------------------------------------------------------------
  std::uint32_t max_name_bytes = 128;
  std::uint32_t max_detail_bytes = 512;

  /// Absolute ceiling for any single count read from a wire frame or a store.
  /// Every count-like field is bounds-checked against the limit that governs
  /// its own collection as well as this ceiling.
  std::uint32_t max_decoded_count = 1u << 24;
};

/// Validates the limit set itself. Zero limits, ceilings above the absolute
/// maximum, or limits that permit unbounded allocation are rejected.
[[nodiscard]] bool validate_limits(const Limits& limits, std::string& why);

/// Absolute ceiling used by ::validate_limits for every count-like limit.
inline constexpr std::uint32_t kAbsoluteMaxLimit = 1u << 27;

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_LIMITS_HPP
