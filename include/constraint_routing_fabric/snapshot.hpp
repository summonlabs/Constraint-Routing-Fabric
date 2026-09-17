// Constraint Routing Fabric -- immutable snapshots, diffs and digests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_SNAPSHOT_HPP
#define CONSTRAINT_ROUTING_FABRIC_SNAPSHOT_HPP

#include <cstdint>
#include <vector>

#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"

namespace crf {

/// Immutable view of a constraint-set definition. Snapshot identity is
/// deterministic: equivalent definitions always share a snapshot id.
struct DefinitionsSnapshot {
  SnapshotId id{};
  ConstraintSetId set_id{};
  ConstraintSetGeneration generation{};
  ConstraintSetState state{ConstraintSetState::Declared};
  std::vector<Constraint> constraints{};
  EvidenceRequirements evidence{};
  RankingPolicy ranking{};
  Digest256 digest{};
};

/// Immutable view of the current authoritative result for one candidate.
struct CandidateResultView {
  PathId path{};
  PathAuthorityGeneration authority_generation{};
  Outcome outcome{Outcome::Malformed};
  ReasonCode primary_reason{ReasonCode::None};
  ResultState state{ResultState::Current};
  ConstraintEvaluationId evaluation_id{};
  EvaluationGeneration evaluation_generation{};
  Digest256 digest{};
};

/// Immutable view of the authoritative results of a constraint set.
struct ResultsSnapshot {
  SnapshotId id{};
  ConstraintSetId set_id{};
  ConstraintSetGeneration set_generation{};
  EvaluationGeneration evaluation_generation{};
  std::vector<CandidateResultView> entries{};
  Digest256 digest{};
};

[[nodiscard]] DefinitionsSnapshot snapshot_definitions(const ConstraintSet& set);
[[nodiscard]] ResultsSnapshot snapshot_results(const ConstraintSetId& set_id,
                                               const ConstraintSetGeneration& set_generation,
                                               const EvaluationGeneration& generation,
                                               std::vector<CandidateResultView> entries);

/// Deterministic identity of a definitions snapshot.
[[nodiscard]] SnapshotId definitions_snapshot_id(const DefinitionsSnapshot& snapshot);
[[nodiscard]] SnapshotId results_snapshot_id(const ResultsSnapshot& snapshot);

enum class ResultChangeKind : std::uint8_t {
  Appeared = 1,
  Disappeared = 2,
  OutcomeChanged = 3,
  ReasonChanged = 4,
  CurrentnessChanged = 5,
  AuthorityGenerationChanged = 6,
  EvidenceDigestChanged = 7,
};

struct ResultChange {
  ResultChangeKind kind{ResultChangeKind::Appeared};
  PathId path{};
  Outcome from_outcome{Outcome::Malformed};
  Outcome to_outcome{Outcome::Malformed};
  ReasonCode from_reason{ReasonCode::None};
  ReasonCode to_reason{ReasonCode::None};
  ResultState from_state{ResultState::Current};
  ResultState to_state{ResultState::Current};
};

struct ResultsDiff {
  SnapshotId from_snapshot{};
  SnapshotId to_snapshot{};
  ConstraintSetGeneration from_generation{};
  ConstraintSetGeneration to_generation{};
  EvaluationGeneration from_evaluation_generation{};
  EvaluationGeneration to_evaluation_generation{};
  std::vector<ResultChange> changes{};
  Digest256 from_digest{};
  Digest256 to_digest{};
};

[[nodiscard]] ResultsDiff diff_results(const ResultsSnapshot& from, const ResultsSnapshot& to);

/// Evidence generation changes are reported separately from candidate changes.
struct EvidenceGenerationChange {
  EvidenceFamily family{EvidenceFamily::None};
  std::uint64_t from_generation{0};
  std::uint64_t to_generation{0};
};

[[nodiscard]] std::vector<EvidenceGenerationChange> diff_evidence_requirements(
    const EvidenceRequirements& from, const EvidenceRequirements& to);

[[nodiscard]] const char* to_string(ResultChangeKind kind) noexcept;

void encode_definitions_snapshot(ByteWriter& writer, const DefinitionsSnapshot& snapshot);
[[nodiscard]] bool decode_definitions_snapshot(ByteReader& reader, const Limits& limits,
                                                DefinitionsSnapshot& out);
void encode_results_snapshot(ByteWriter& writer, const ResultsSnapshot& snapshot);
[[nodiscard]] bool decode_results_snapshot(ByteReader& reader, const Limits& limits, ResultsSnapshot& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_SNAPSHOT_HPP
