// Constraint Routing Fabric -- immutable snapshots and deterministic diffs.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/snapshot.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <string>

namespace crf {
namespace {

void feed_entry(SemanticHasher& hasher, const CandidateResultView& entry) {
  hasher.put_u64(entry.path.value());
  hasher.put_u64(entry.authority_generation.value());
  hasher.put_u16(static_cast<std::uint16_t>(entry.outcome));
  hasher.put_u16(static_cast<std::uint16_t>(entry.primary_reason));
  hasher.put_u8(static_cast<std::uint8_t>(entry.state));
  hasher.put_u64(entry.evaluation_id.value());
  hasher.put_u64(entry.evaluation_generation.value());
  hasher.put_digest(entry.digest);
}

void feed_evidence(SemanticHasher& hasher, const EvidenceRequirements& evidence) {
  hasher.put_u64(evidence.topology.value());
  hasher.put_u64(evidence.link_state.value());
  hasher.put_u64(evidence.capability.value());
  hasher.put_u64(evidence.failure_domain.value());
  hasher.put_u64(evidence.policy.value());
  hasher.put_u64(evidence.planner.value());
  hasher.put_u64(evidence.path_authority.value());
  hasher.put_u64(evidence.max_evidence_age_ticks);
}

template <class Tag>
[[nodiscard]] bool read_generation_field(ByteReader& reader, Generation<Tag>& out) {
  std::uint64_t raw = 0;
  if (!reader.u64(raw)) {
    return false;
  }
  if (raw == 0) {
    out = Generation<Tag>{};
    return true;
  }
  if (!Generation<Tag>::is_representable(raw)) {
    reader.fail();
    return false;
  }
  out = Generation<Tag>::from_value(raw);
  return true;
}

void write_evidence(ByteWriter& writer, const EvidenceRequirements& evidence) {
  writer.put_u64(evidence.topology.value());
  writer.put_u64(evidence.link_state.value());
  writer.put_u64(evidence.capability.value());
  writer.put_u64(evidence.failure_domain.value());
  writer.put_u64(evidence.policy.value());
  writer.put_u64(evidence.planner.value());
  writer.put_u64(evidence.path_authority.value());
  writer.put_u64(evidence.max_evidence_age_ticks);
}

[[nodiscard]] bool read_evidence(ByteReader& reader, EvidenceRequirements& out) {
  return read_generation_field(reader, out.topology) &&
         read_generation_field(reader, out.link_state) &&
         read_generation_field(reader, out.capability) &&
         read_generation_field(reader, out.failure_domain) &&
         read_generation_field(reader, out.policy) && read_generation_field(reader, out.planner) &&
         read_generation_field(reader, out.path_authority) &&
         reader.u64(out.max_evidence_age_ticks);
}

}  // namespace

DefinitionsSnapshot snapshot_definitions(const ConstraintSet& set) {
  DefinitionsSnapshot snapshot;
  snapshot.set_id = set.id;
  snapshot.generation = set.generation;
  snapshot.state = set.state;
  snapshot.constraints = set.constraints;
  snapshot.evidence = set.evidence;
  snapshot.ranking = set.ranking;
  snapshot.digest = set.digest;
  snapshot.id = definitions_snapshot_id(snapshot);
  return snapshot;
}

SnapshotId definitions_snapshot_id(const DefinitionsSnapshot& snapshot) {
  SemanticHasher hasher;
  hasher.begin("crf.definitions-snapshot.v1");
  hasher.put_u64(snapshot.set_id.value());
  hasher.put_u64(snapshot.generation.value());
  hasher.put_u8(static_cast<std::uint8_t>(snapshot.state));
  hasher.put_digest(snapshot.digest);
  const std::uint64_t value = hasher.finish().leading_u64();
  return SnapshotId::from_value(value == 0 ? 1u : value);
}

ResultsSnapshot snapshot_results(const ConstraintSetId& set_id,
                                 const ConstraintSetGeneration& set_generation,
                                 const EvaluationGeneration& generation,
                                 std::vector<CandidateResultView> entries) {
  std::stable_sort(entries.begin(), entries.end(),
                   [](const CandidateResultView& a, const CandidateResultView& b) {
                     if (a.path != b.path) return a.path < b.path;
                     return a.evaluation_generation < b.evaluation_generation;
                   });
  ResultsSnapshot snapshot;
  snapshot.set_id = set_id;
  snapshot.set_generation = set_generation;
  snapshot.evaluation_generation = generation;
  snapshot.entries = std::move(entries);
  SemanticHasher hasher;
  hasher.begin("crf.results-snapshot.v1");
  hasher.put_u64(snapshot.set_id.value());
  hasher.put_u64(snapshot.set_generation.value());
  hasher.put_u64(snapshot.evaluation_generation.value());
  hasher.put_u32(static_cast<std::uint32_t>(snapshot.entries.size()));
  for (const CandidateResultView& entry : snapshot.entries) {
    feed_entry(hasher, entry);
  }
  snapshot.digest = hasher.finish();
  snapshot.id = results_snapshot_id(snapshot);
  return snapshot;
}

SnapshotId results_snapshot_id(const ResultsSnapshot& snapshot) {
  const std::uint64_t value = snapshot.digest.leading_u64();
  return SnapshotId::from_value(value == 0 ? 1u : value);
}

ResultsDiff diff_results(const ResultsSnapshot& from, const ResultsSnapshot& to) {
  ResultsDiff diff;
  diff.from_snapshot = from.id;
  diff.to_snapshot = to.id;
  diff.from_generation = from.set_generation;
  diff.to_generation = to.set_generation;
  diff.from_evaluation_generation = from.evaluation_generation;
  diff.to_evaluation_generation = to.evaluation_generation;
  diff.from_digest = from.digest;
  diff.to_digest = to.digest;

  std::map<std::uint64_t, const CandidateResultView*> left;
  for (const CandidateResultView& entry : from.entries) {
    if (left.find(entry.path.value()) == left.end()) {
      left.emplace(entry.path.value(), &entry);
    } else {
      // Only the newest result per path participates in a diff.
      CandidateResultView* previous = const_cast<CandidateResultView*>(left[entry.path.value()]);
      if (previous->evaluation_generation < entry.evaluation_generation) {
        left[entry.path.value()] = &entry;
      }
    }
  }
  std::map<std::uint64_t, const CandidateResultView*> right;
  for (const CandidateResultView& entry : to.entries) {
    if (right.find(entry.path.value()) == right.end()) {
      right.emplace(entry.path.value(), &entry);
    } else {
      CandidateResultView* previous = const_cast<CandidateResultView*>(right[entry.path.value()]);
      if (previous->evaluation_generation < entry.evaluation_generation) {
        right[entry.path.value()] = &entry;
      }
    }
  }

  for (const auto& entry : left) {
    const auto found = right.find(entry.first);
    if (found == right.end()) {
      ResultChange change;
      change.kind = ResultChangeKind::Disappeared;
      change.path = entry.second->path;
      change.from_outcome = entry.second->outcome;
      change.from_reason = entry.second->primary_reason;
      change.from_state = entry.second->state;
      diff.changes.push_back(change);
      continue;
    }
    const CandidateResultView& before = *entry.second;
    const CandidateResultView& after = *found->second;
    if (before.outcome != after.outcome) {
      ResultChange change;
      change.kind = ResultChangeKind::OutcomeChanged;
      change.path = before.path;
      change.from_outcome = before.outcome;
      change.to_outcome = after.outcome;
      change.from_reason = before.primary_reason;
      change.to_reason = after.primary_reason;
      change.from_state = before.state;
      change.to_state = after.state;
      diff.changes.push_back(change);
    } else if (before.primary_reason != after.primary_reason) {
      ResultChange change;
      change.kind = ResultChangeKind::ReasonChanged;
      change.path = before.path;
      change.from_outcome = before.outcome;
      change.to_outcome = after.outcome;
      change.from_reason = before.primary_reason;
      change.to_reason = after.primary_reason;
      change.from_state = before.state;
      change.to_state = after.state;
      diff.changes.push_back(change);
    } else if (before.state != after.state) {
      ResultChange change;
      change.kind = ResultChangeKind::CurrentnessChanged;
      change.path = before.path;
      change.from_state = before.state;
      change.to_state = after.state;
      diff.changes.push_back(change);
    } else if (!(before.authority_generation == after.authority_generation)) {
      ResultChange change;
      change.kind = ResultChangeKind::AuthorityGenerationChanged;
      change.path = before.path;
      change.from_state = before.state;
      change.to_state = after.state;
      diff.changes.push_back(change);
    } else if (!(before.digest == after.digest)) {
      ResultChange change;
      change.kind = ResultChangeKind::EvidenceDigestChanged;
      change.path = before.path;
      change.from_state = before.state;
      change.to_state = after.state;
      diff.changes.push_back(change);
    }
  }
  for (const auto& entry : right) {
    if (left.find(entry.first) == left.end()) {
      ResultChange change;
      change.kind = ResultChangeKind::Appeared;
      change.path = entry.second->path;
      change.to_outcome = entry.second->outcome;
      change.to_reason = entry.second->primary_reason;
      change.to_state = entry.second->state;
      diff.changes.push_back(change);
    }
  }
  std::sort(diff.changes.begin(), diff.changes.end(),
            [](const ResultChange& a, const ResultChange& b) {
              if (a.path != b.path) return a.path < b.path;
              if (a.kind != b.kind) return a.kind < b.kind;
              return a.to_reason < b.to_reason;
            });
  return diff;
}

std::vector<EvidenceGenerationChange> diff_evidence_requirements(const EvidenceRequirements& from,
                                                                 const EvidenceRequirements& to) {
  std::vector<EvidenceGenerationChange> changes;
  const auto add = [&changes](EvidenceFamily family, std::uint64_t before, std::uint64_t after) {
    if (before != after) {
      changes.push_back(EvidenceGenerationChange{family, before, after});
    }
  };
  add(EvidenceFamily::Topology, from.topology.value(), to.topology.value());
  add(EvidenceFamily::LinkState, from.link_state.value(), to.link_state.value());
  add(EvidenceFamily::Capability, from.capability.value(), to.capability.value());
  add(EvidenceFamily::FailureDomain, from.failure_domain.value(), to.failure_domain.value());
  add(EvidenceFamily::Policy, from.policy.value(), to.policy.value());
  add(EvidenceFamily::Planner, from.planner.value(), to.planner.value());
  add(EvidenceFamily::PathAuthority, from.path_authority.value(), to.path_authority.value());
  return changes;
}

const char* to_string(ResultChangeKind kind) noexcept {
  switch (kind) {
    case ResultChangeKind::Appeared: return "Appeared";
    case ResultChangeKind::Disappeared: return "Disappeared";
    case ResultChangeKind::OutcomeChanged: return "OutcomeChanged";
    case ResultChangeKind::ReasonChanged: return "ReasonChanged";
    case ResultChangeKind::CurrentnessChanged: return "CurrentnessChanged";
    case ResultChangeKind::AuthorityGenerationChanged: return "AuthorityGenerationChanged";
    case ResultChangeKind::EvidenceDigestChanged: return "EvidenceDigestChanged";
  }
  return "Unknown";
}

void encode_definitions_snapshot(ByteWriter& writer, const DefinitionsSnapshot& snapshot) {
  writer.put_u64(snapshot.id.value());
  writer.put_u64(snapshot.set_id.value());
  writer.put_u64(snapshot.generation.value());
  writer.put_u8(static_cast<std::uint8_t>(snapshot.state));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u32(static_cast<std::uint32_t>(snapshot.constraints.size()));
  for (const Constraint& constraint : snapshot.constraints) {
    encode_constraint(writer, constraint);
  }
  write_evidence(writer, snapshot.evidence);
  encode_ranking_policy(writer, snapshot.ranking);
  writer.put_raw(std::span<const std::byte>(snapshot.digest.data(), Digest256::kSize));
}

bool decode_definitions_snapshot(ByteReader& reader, const Limits& limits,
                                 DefinitionsSnapshot& out) {
  std::uint64_t id = 0;
  std::uint64_t set_id = 0;
  std::uint64_t generation = 0;
  std::uint8_t state = 0;
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.u64(id) || !reader.u64(set_id) || !reader.u64(generation) || !reader.u8(state) ||
      !reader.u8(padding8) || !reader.u16(padding16) || !reader.u32(padding32)) {
    return false;
  }
  if (padding8 != 0 || padding16 != 0 || padding32 != 0 || state == 0 || state > 7) {
    reader.fail();
    return false;
  }
  out.id = SnapshotId::from_value(id);
  out.set_id = ConstraintSetId::from_value(set_id);
  out.state = static_cast<ConstraintSetState>(state);
  if (generation != 0) {
    if (!ConstraintSetGeneration::is_representable(generation)) {
      reader.fail();
      return false;
    }
    out.generation = ConstraintSetGeneration::from_value(generation);
  }
  std::uint32_t count = 0;
  if (!reader.bounded_length(limits.max_constraints_per_set, count)) {
    return false;
  }
  out.constraints.clear();
  out.constraints.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    Constraint constraint;
    if (!decode_constraint(reader, limits, constraint)) {
      return false;
    }
    out.constraints.push_back(std::move(constraint));
  }
  if (!read_evidence(reader, out.evidence) || !decode_ranking_policy(reader, out.ranking)) {
    return false;
  }
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes))) {
    return false;
  }
  out.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  return reader.ok();
}

void encode_results_snapshot(ByteWriter& writer, const ResultsSnapshot& snapshot) {
  writer.put_u64(snapshot.id.value());
  writer.put_u64(snapshot.set_id.value());
  writer.put_u64(snapshot.set_generation.value());
  writer.put_u64(snapshot.evaluation_generation.value());
  writer.put_u32(static_cast<std::uint32_t>(snapshot.entries.size()));
  for (const CandidateResultView& entry : snapshot.entries) {
    writer.put_u64(entry.path.value());
    writer.put_u64(entry.authority_generation.value());
    writer.put_u16(static_cast<std::uint16_t>(entry.outcome));
    writer.put_u16(static_cast<std::uint16_t>(entry.primary_reason));
    writer.put_u8(static_cast<std::uint8_t>(entry.state));
    writer.put_u8(0);
    writer.put_u16(0);
    writer.put_u64(entry.evaluation_id.value());
    writer.put_u64(entry.evaluation_generation.value());
    writer.put_raw(std::span<const std::byte>(entry.digest.data(), Digest256::kSize));
  }
  writer.put_raw(std::span<const std::byte>(snapshot.digest.data(), Digest256::kSize));
}

bool decode_results_snapshot(ByteReader& reader, const Limits& limits, ResultsSnapshot& out) {
  std::uint64_t id = 0;
  std::uint64_t set_id = 0;
  std::uint64_t set_generation = 0;
  std::uint64_t evaluation_generation = 0;
  if (!reader.u64(id) || !reader.u64(set_id) || !reader.u64(set_generation) ||
      !reader.u64(evaluation_generation)) {
    return false;
  }
  out.id = SnapshotId::from_value(id);
  out.set_id = ConstraintSetId::from_value(set_id);
  if (set_generation != 0) {
    if (!ConstraintSetGeneration::is_representable(set_generation)) {
      reader.fail();
      return false;
    }
    out.set_generation = ConstraintSetGeneration::from_value(set_generation);
  }
  if (evaluation_generation != 0) {
    if (!EvaluationGeneration::is_representable(evaluation_generation)) {
      reader.fail();
      return false;
    }
    out.evaluation_generation = EvaluationGeneration::from_value(evaluation_generation);
  }
  std::uint32_t count = 0;
  if (!reader.bounded_length(limits.max_evaluations_retained, count)) {
    return false;
  }
  out.entries.clear();
  out.entries.reserve(count);
  CandidateResultView previous;
  bool has_previous = false;
  for (std::uint32_t index = 0; index < count; ++index) {
    CandidateResultView entry;
    std::uint64_t path = 0;
    std::uint64_t authority = 0;
    std::uint16_t outcome = 0;
    std::uint16_t reason = 0;
    std::uint8_t state = 0;
    std::uint8_t padding8 = 0;
    std::uint16_t padding16 = 0;
    std::uint64_t evaluation_id = 0;
    std::uint64_t evaluation_generation_value = 0;
    if (!reader.u64(path) || !reader.u64(authority) || !reader.u16(outcome) ||
        !reader.u16(reason) || !reader.u8(state) || !reader.u8(padding8) ||
        !reader.u16(padding16) || !reader.u64(evaluation_id) ||
        !reader.u64(evaluation_generation_value)) {
      return false;
    }
    if (padding8 != 0 || padding16 != 0 || outcome > 10 || state == 0 || state > 5 || path == 0) {
      reader.fail();
      return false;
    }
    std::array<std::byte, Digest256::kSize> digest_bytes{};
    if (!reader.raw(std::span<std::byte>(digest_bytes))) {
      return false;
    }
    entry.path = PathId::from_value(path);
    if (authority != 0) {
      if (!PathAuthorityGeneration::is_representable(authority)) {
        reader.fail();
        return false;
      }
      entry.authority_generation = PathAuthorityGeneration::from_value(authority);
    }
    entry.outcome = static_cast<Outcome>(outcome);
    entry.primary_reason = static_cast<ReasonCode>(reason);
    entry.state = static_cast<ResultState>(state);
    entry.evaluation_id = ConstraintEvaluationId::from_value(evaluation_id);
    if (evaluation_generation_value != 0) {
      if (!EvaluationGeneration::is_representable(evaluation_generation_value)) {
        reader.fail();
        return false;
      }
      entry.evaluation_generation = EvaluationGeneration::from_value(evaluation_generation_value);
    }
    entry.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
    if (has_previous && !(previous.path < entry.path)) {
      reader.fail();
      return false;
    }
    previous = entry;
    has_previous = true;
    out.entries.push_back(std::move(entry));
  }
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes))) {
    return false;
  }
  out.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  return reader.ok();
}

}  // namespace crf
