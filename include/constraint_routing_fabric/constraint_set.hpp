// Constraint Routing Fabric -- constraint sets, canonicalization and contradictions.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_SET_HPP
#define CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_SET_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/lifecycle.hpp"
#include "constraint_routing_fabric/ordering.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Kind of deterministic contradiction found in a constraint set.
enum class ContradictionKind : std::uint8_t {
  RequiredAndForbiddenSameEntity = 1,
  ConflictingLocalityScopes = 2,
  ConflictingIsolationClasses = 3,
  FailureDomainRelationConflict = 4,
  ImpossibleHopBudget = 5,
};

struct Contradiction {
  ContradictionKind kind{ContradictionKind::RequiredAndForbiddenSameEntity};
  ConstraintId first{};
  ConstraintId second{};
  SubjectKind subject_kind{SubjectKind::None};
  std::uint64_t subject{0};
};

[[nodiscard]] const char* to_string(ContradictionKind kind) noexcept;

/// Non-fatal structural observation recorded during canonicalization.
enum class SetDefectKind : std::uint8_t {
  EquivalentDuplicateCollapsed = 1,
  EntityListReordered = 2,
  DuplicateEntityCollapsed = 3,
  ConstraintsReordered = 4,
};

struct SetDefect {
  SetDefectKind kind{SetDefectKind::ConstraintsReordered};
  ConstraintId constraint{};
  std::uint32_t count{0};
};

/// A declared set of mandatory and preference constraints with an exact
/// evidence binding and an explicit ranking policy. The semantic digest covers
/// constraint content, evidence requirements and ranking policy only: the
/// human-readable name and declaration tick are excluded.
struct ConstraintSet {
  ConstraintSetId id{};
  ConstraintSetGeneration generation{};
  ConstraintSetState state{ConstraintSetState::Declared};
  std::string name{};
  std::vector<Constraint> constraints{};
  EvidenceRequirements evidence{};
  RankingPolicy ranking{};
  Digest256 digest{};
  std::uint64_t declared_tick{0};
};

/// Canonicalizes in place: sorts constraints into canonical order, collapses
/// equivalent duplicates, sorts and de-duplicates entity lists, and recomputes
/// the semantic digest. Returns the observations it made.
[[nodiscard]] Status canonicalize_constraint_set(ConstraintSet& set,
                                                 const Limits& limits,
                                                 std::vector<SetDefect>& defects);

/// Validates structure, canonicalizes, then detects contradictions. A
/// contradictory set is rejected atomically: \p set is left untouched.
[[nodiscard]] Status validate_and_finalize_constraint_set(ConstraintSet& set,
                                                          const Limits& limits,
                                                          std::vector<SetDefect>& defects,
                                                          std::vector<Contradiction>& contradictions);

/// Detects deterministic contradictions on an already canonical set.
[[nodiscard]] Status detect_contradictions(const ConstraintSet& set,
                                           const Limits& limits,
                                           std::vector<Contradiction>& out);

/// Semantic digest of a canonical constraint set.
[[nodiscard]] Digest256 constraint_set_digest(const ConstraintSet& set);

/// Deterministic diff between two definitions of the same set.
enum class ConstraintChangeKind : std::uint8_t {
  Added = 1,
  Removed = 2,
  Changed = 3,
};

struct ConstraintChange {
  ConstraintChangeKind kind{ConstraintChangeKind::Added};
  ConstraintId constraint{};
  ConstraintKind constraint_kind{ConstraintKind::Unset};
};

struct ConstraintSetDiff {
  ConstraintSetId set_id{};
  ConstraintSetGeneration from_generation{};
  ConstraintSetGeneration to_generation{};
  bool evidence_requirements_changed{false};
  bool ranking_policy_changed{false};
  bool lifecycle_changed{false};
  ConstraintSetState from_state{ConstraintSetState::Declared};
  ConstraintSetState to_state{ConstraintSetState::Declared};
  std::vector<ConstraintChange> changes{};
  Digest256 from_digest{};
  Digest256 to_digest{};
};

[[nodiscard]] ConstraintSetDiff diff_constraint_sets(const ConstraintSet& from, const ConstraintSet& to);

void encode_constraint_set(ByteWriter& writer, const ConstraintSet& set);
[[nodiscard]] bool decode_constraint_set(ByteReader& reader, const Limits& limits, ConstraintSet& out);

/// Validates an already decoded set (canonical order, digest, contradiction-free).
[[nodiscard]] Status verify_canonical_constraint_set(const ConstraintSet& set, const Limits& limits);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_SET_HPP
