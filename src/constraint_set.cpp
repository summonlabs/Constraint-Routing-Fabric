// Constraint Routing Fabric -- constraint sets, canonicalization, contradictions.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/constraint_set.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace crf {
namespace {

[[nodiscard]] Status malformed(const std::string& detail) {
  return Status::failure(ErrorCode::Malformed, detail);
}

template <class Id>
[[nodiscard]] bool sorted_unique(const std::vector<Id>& values) {
  for (std::size_t index = 1; index < values.size(); ++index) {
    if (!(values[index - 1] < values[index])) {
      return false;
    }
  }
  return true;
}

void feed_evidence_requirements(SemanticHasher& hasher, const EvidenceRequirements& evidence) {
  hasher.put_u64(evidence.topology.value());
  hasher.put_u64(evidence.link_state.value());
  hasher.put_u64(evidence.capability.value());
  hasher.put_u64(evidence.failure_domain.value());
  hasher.put_u64(evidence.policy.value());
  hasher.put_u64(evidence.planner.value());
  hasher.put_u64(evidence.path_authority.value());
  hasher.put_u64(evidence.max_evidence_age_ticks);
}

struct Bucket {
  const Constraint* constraint;
  std::uint32_t ordinal;
};

[[nodiscard]] std::vector<Bucket> bucket_of(const ConstraintSet& set, ConstraintKind kind) {
  std::vector<Bucket> bucket;
  for (std::uint32_t index = 0; index < set.constraints.size(); ++index) {
    if (set.constraints[index].kind == kind) {
      bucket.push_back(Bucket{&set.constraints[index], index});
    }
  }
  return bucket;
}

template <class Id>
void add_same_entity_contradictions(const std::vector<Bucket>& required,
                                    const std::vector<Bucket>& forbidden,
                                    SubjectKind subject_kind,
                                    std::vector<Id> Constraint::*member,
                                    std::vector<Contradiction>& out) {
  for (const Bucket& positive : required) {
    for (const Bucket& negative : forbidden) {
      for (const Id& value : positive.constraint->*member) {
        const std::vector<Id>& other = negative.constraint->*member;
        if (std::binary_search(other.begin(), other.end(), value)) {
          Contradiction contradiction;
          contradiction.kind = ContradictionKind::RequiredAndForbiddenSameEntity;
          contradiction.first = positive.constraint->id;
          contradiction.second = negative.constraint->id;
          contradiction.subject_kind = subject_kind;
          contradiction.subject = value.value();
          out.push_back(contradiction);
        }
      }
    }
  }
}

}  // namespace

const char* to_string(ContradictionKind kind) noexcept {
  switch (kind) {
    case ContradictionKind::RequiredAndForbiddenSameEntity: return "RequiredAndForbiddenSameEntity";
    case ContradictionKind::ConflictingLocalityScopes: return "ConflictingLocalityScopes";
    case ContradictionKind::ConflictingIsolationClasses: return "ConflictingIsolationClasses";
    case ContradictionKind::FailureDomainRelationConflict: return "FailureDomainRelationConflict";
    case ContradictionKind::ImpossibleHopBudget: return "ImpossibleHopBudget";
  }
  return "Unknown";
}

Status detect_contradictions(const ConstraintSet& set, const Limits& limits,
                             std::vector<Contradiction>& out) {
  out.clear();
  if (set.constraints.size() > limits.max_constraints_per_set) {
    return Status::failure(ErrorCode::ResourceLimit, "constraint set exceeds the constraint limit");
  }

  add_same_entity_contradictions(bucket_of(set, ConstraintKind::RequiredNode),
                                 bucket_of(set, ConstraintKind::ForbiddenNode), SubjectKind::Node,
                                 &Constraint::nodes, out);
  add_same_entity_contradictions(bucket_of(set, ConstraintKind::RequiredLink),
                                 bucket_of(set, ConstraintKind::ForbiddenLink), SubjectKind::Link,
                                 &Constraint::links, out);
  add_same_entity_contradictions(bucket_of(set, ConstraintKind::RequiredTier),
                                 bucket_of(set, ConstraintKind::ForbiddenTier), SubjectKind::Tier,
                                 &Constraint::tiers, out);
  add_same_entity_contradictions(bucket_of(set, ConstraintKind::RequiredSite),
                                 bucket_of(set, ConstraintKind::ForbiddenSite), SubjectKind::Site,
                                 &Constraint::sites, out);
  add_same_entity_contradictions(bucket_of(set, ConstraintKind::RequiredCapability),
                                 bucket_of(set, ConstraintKind::ForbiddenCapability),
                                 SubjectKind::Capability, &Constraint::capabilities, out);

  // Conflicting locality scopes: a path cannot be confined to two different
  // domains of the same authoritative kind.
  const std::vector<Bucket> localities = bucket_of(set, ConstraintKind::LocalityScope);
  for (std::size_t a = 0; a < localities.size(); ++a) {
    for (std::size_t b = a + 1; b < localities.size(); ++b) {
      if (localities[a].constraint->domain_kind == localities[b].constraint->domain_kind &&
          localities[a].constraint->locality_domain != localities[b].constraint->locality_domain) {
        Contradiction contradiction;
        contradiction.kind = ContradictionKind::ConflictingLocalityScopes;
        contradiction.first = localities[a].constraint->id;
        contradiction.second = localities[b].constraint->id;
        contradiction.subject_kind = SubjectKind::LocalityDomain;
        contradiction.subject = localities[b].constraint->locality_domain.value();
        out.push_back(contradiction);
      }
    }
  }

  // Conflicting isolation classes: a path is proven to be in exactly one class.
  const std::vector<Bucket> isolation = bucket_of(set, ConstraintKind::IsolationClass);
  for (std::size_t a = 0; a < isolation.size(); ++a) {
    for (std::size_t b = a + 1; b < isolation.size(); ++b) {
      if (isolation[a].constraint->isolation_class != isolation[b].constraint->isolation_class) {
        Contradiction contradiction;
        contradiction.kind = ContradictionKind::ConflictingIsolationClasses;
        contradiction.first = isolation[a].constraint->id;
        contradiction.second = isolation[b].constraint->id;
        contradiction.subject_kind = SubjectKind::IsolationClass;
        contradiction.subject = isolation[b].constraint->isolation_class.value();
        out.push_back(contradiction);
      }
    }
  }

  // Failure-domain relation algebra. Required/Distinct(n) with n >= 2 excludes a
  // fully shared domain, and a forbidden distinct count below the required count
  // is unsatisfiable.
  const std::vector<Bucket> required_relations =
      bucket_of(set, ConstraintKind::RequiredFailureDomainRelation);
  const std::vector<Bucket> forbidden_relations =
      bucket_of(set, ConstraintKind::ForbiddenFailureDomainRelation);
  for (const Bucket& required : required_relations) {
    for (const Bucket& forbidden : forbidden_relations) {
      if (required.constraint->domain_kind != forbidden.constraint->domain_kind) {
        continue;
      }
      bool conflict = false;
      if (forbidden.constraint->domain_relation == DomainRelation::Shared) {
        conflict = required.constraint->bound >= 2;
      } else if (forbidden.constraint->domain_relation == DomainRelation::Distinct) {
        conflict = forbidden.constraint->bound <= required.constraint->bound;
      }
      if (conflict) {
        Contradiction contradiction;
        contradiction.kind = ContradictionKind::FailureDomainRelationConflict;
        contradiction.first = required.constraint->id;
        contradiction.second = forbidden.constraint->id;
        contradiction.subject_kind = SubjectKind::FailureDomain;
        contradiction.subject = static_cast<std::uint64_t>(required.constraint->domain_kind);
        out.push_back(contradiction);
      }
    }
  }

  // Impossible hop budget: every distinct required node must appear on the
  // path, so the path needs at least (distinct required nodes - 1) hops.
  std::set<std::uint64_t> required_nodes;
  for (const Bucket& bucket : bucket_of(set, ConstraintKind::RequiredNode)) {
    for (const NodeId& node : bucket.constraint->nodes) {
      required_nodes.insert(node.value());
    }
  }
  for (const Bucket& bucket : bucket_of(set, ConstraintKind::MaxHopCount)) {
    const std::int64_t budget = bucket.constraint->bound;
    const auto needed = static_cast<std::int64_t>(required_nodes.size()) - 1;
    if (needed > budget) {
      Contradiction contradiction;
      contradiction.kind = ContradictionKind::ImpossibleHopBudget;
      contradiction.first = bucket.constraint->id;
      contradiction.second = ConstraintId{};
      contradiction.subject_kind = SubjectKind::Constraint;
      contradiction.subject = static_cast<std::uint64_t>(needed);
      out.push_back(contradiction);
    }
  }

  if (!out.empty()) {
    return Status::failure(ErrorCode::ContradictoryConstraintSet,
                           "constraint set contains a deterministic contradiction");
  }
  return Status::success();
}

Status canonicalize_constraint_set(ConstraintSet& set, const Limits& limits,
                                   std::vector<SetDefect>& defects) {
  defects.clear();
  std::string why;
  if (!validate_limits(limits, why)) {
    return Status::failure(ErrorCode::InvalidArgument, why);
  }
  if (!set.id.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "constraint set identity must be non-zero");
  }
  if (!set.generation.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "constraint set generation must be non-zero");
  }
  if (set.constraints.size() > limits.max_constraints_per_set) {
    return Status::failure(ErrorCode::ResourceLimit, "constraint set exceeds the constraint limit");
  }
  if (set.name.size() > limits.max_name_bytes) {
    return Status::failure(ErrorCode::ResourceLimit, "constraint set name exceeds the name limit");
  }

  // One observation per entity list that actually changed, in a fixed list
  // order, so the defect report is deterministic and complete.
  const auto canonicalize_entity_list = [&defects](auto& list, const ConstraintId& id) {
    const auto before = list;
    std::sort(list.begin(), list.end());
    const auto unique_end = std::unique(list.begin(), list.end());
    const bool duplicates = unique_end != list.end();
    list.erase(unique_end, list.end());
    if (duplicates) {
      defects.push_back(SetDefect{SetDefectKind::DuplicateEntityCollapsed, id, 1});
    } else if (list != before) {
      defects.push_back(SetDefect{SetDefectKind::EntityListReordered, id, 1});
    }
  };

  for (Constraint& constraint : set.constraints) {
    const Status status = validate_constraint(constraint, limits);
    if (!status.ok()) {
      return status;
    }
    canonicalize_entity_list(constraint.nodes, constraint.id);
    canonicalize_entity_list(constraint.links, constraint.id);
    canonicalize_entity_list(constraint.tiers, constraint.id);
    canonicalize_entity_list(constraint.sites, constraint.id);
    canonicalize_entity_list(constraint.capabilities, constraint.id);
    canonicalize_entity_list(constraint.policies, constraint.id);
  }

  // Duplicate identity: the same ConstraintId may not describe two different
  // constraints. Equivalent duplicates under *different* ids collapse below.
  std::map<ConstraintId, std::vector<std::byte>> payloads;
  for (const Constraint& constraint : set.constraints) {
    const std::vector<std::byte> payload = encode_constraint_payload(constraint);
    const auto found = payloads.find(constraint.id);
    if (found == payloads.end()) {
      payloads.emplace(constraint.id, payload);
    } else if (found->second != payload) {
      return Status::failure(ErrorCode::DuplicateIdentity,
                             "the same constraint identity describes two different constraints");
    }
  }

  const std::vector<Constraint> before = set.constraints;
  std::stable_sort(set.constraints.begin(), set.constraints.end(),
                   [](const Constraint& a, const Constraint& b) { return canonical_less(a, b); });

  std::vector<Constraint> collapsed;
  collapsed.reserve(set.constraints.size());
  for (const Constraint& constraint : set.constraints) {
    if (!collapsed.empty() && equivalent_payload(collapsed.back(), constraint)) {
      SetDefect defect;
      defect.kind = SetDefectKind::EquivalentDuplicateCollapsed;
      defect.constraint = collapsed.back().id;
      defect.count = 1;
      defects.push_back(defect);
      continue;
    }
    collapsed.push_back(constraint);
  }
  set.constraints = std::move(collapsed);

  if (set.constraints.size() != before.size()) {
    bool reorder_recorded = false;
    for (const SetDefect& defect : defects) {
      if (defect.kind == SetDefectKind::ConstraintsReordered) {
        reorder_recorded = true;
      }
    }
    if (!reorder_recorded) {
      SetDefect defect;
      defect.kind = SetDefectKind::ConstraintsReordered;
      defect.count = static_cast<std::uint32_t>(before.size());
      defects.push_back(defect);
    }
  } else {
    for (std::size_t index = 0; index < before.size(); ++index) {
      if (!(before[index].id == set.constraints[index].id)) {
        SetDefect defect;
        defect.kind = SetDefectKind::ConstraintsReordered;
        defect.count = static_cast<std::uint32_t>(before.size());
        defects.push_back(defect);
        break;
      }
    }
  }

  set.digest = constraint_set_digest(set);
  return Status::success();
}

Status validate_and_finalize_constraint_set(ConstraintSet& set, const Limits& limits,
                                            std::vector<SetDefect>& defects,
                                            std::vector<Contradiction>& contradictions) {
  ConstraintSet working = set;
  const Status status = canonicalize_constraint_set(working, limits, defects);
  if (!status.ok()) {
    return status;
  }
  const Status contradiction_status = detect_contradictions(working, limits, contradictions);
  if (!contradiction_status.ok()) {
    // Atomic rejection: the caller's set is left exactly as it was.
    return contradiction_status;
  }
  set = std::move(working);
  return Status::success();
}

Digest256 constraint_set_digest(const ConstraintSet& set) {
  SemanticHasher hasher;
  hasher.begin("crf.constraint-set.v1");
  hasher.put_u64(set.id.value());
  hasher.put_u64(set.generation.value());
  hasher.put_u32(static_cast<std::uint32_t>(set.constraints.size()));
  for (const Constraint& constraint : set.constraints) {
    feed_digest(hasher, constraint);
  }
  feed_evidence_requirements(hasher, set.evidence);
  feed_digest(hasher, set.ranking);
  // The lifecycle state and the human-readable name are deliberately excluded:
  // they are tracked by the lifecycle and snapshot axes, not by the definition
  // digest, so two semantically equal definitions always digest identically.
  return hasher.finish();
}

Status verify_canonical_constraint_set(const ConstraintSet& set, const Limits& limits) {
  if (!set.id.is_valid() || !set.generation.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "constraint set identity must be non-zero");
  }
  if (set.constraints.size() > limits.max_constraints_per_set) {
    return Status::failure(ErrorCode::ResourceLimit, "constraint set exceeds the constraint limit");
  }
  ConstraintId previous_id{};
  bool has_previous = false;
  for (std::size_t index = 0; index < set.constraints.size(); ++index) {
    const Constraint& constraint = set.constraints[index];
    const Status status = validate_constraint(constraint, limits);
    if (!status.ok()) {
      return status;
    }
    if (!sorted_unique(constraint.nodes) || !sorted_unique(constraint.links) ||
        !sorted_unique(constraint.tiers) || !sorted_unique(constraint.sites) ||
        !sorted_unique(constraint.capabilities) || !sorted_unique(constraint.policies)) {
      return malformed("persisted constraint entity lists are not canonical");
    }
    if (index > 0 && !canonical_less(set.constraints[index - 1], constraint)) {
      return malformed("persisted constraint ordering is not canonical");
    }
    if (has_previous && previous_id == constraint.id && index > 0) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate constraint identity");
    }
    previous_id = constraint.id;
    has_previous = true;
  }
  const Digest256 recomputed = constraint_set_digest(set);
  if (recomputed != set.digest) {
    return Status::failure(ErrorCode::IntegrityMismatch,
                           "constraint set digest does not match its content");
  }
  std::vector<Contradiction> contradictions;
  return detect_contradictions(set, limits, contradictions);
}

ConstraintSetDiff diff_constraint_sets(const ConstraintSet& from, const ConstraintSet& to) {
  ConstraintSetDiff diff;
  diff.set_id = to.id;
  diff.from_generation = from.generation;
  diff.to_generation = to.generation;
  diff.from_state = from.state;
  diff.to_state = to.state;
  diff.lifecycle_changed = from.state != to.state;
  diff.evidence_requirements_changed =
      from.evidence.topology != to.evidence.topology ||
      from.evidence.link_state != to.evidence.link_state ||
      from.evidence.capability != to.evidence.capability ||
      from.evidence.failure_domain != to.evidence.failure_domain ||
      from.evidence.policy != to.evidence.policy || from.evidence.planner != to.evidence.planner ||
      from.evidence.path_authority != to.evidence.path_authority ||
      from.evidence.max_evidence_age_ticks != to.evidence.max_evidence_age_ticks;
  diff.ranking_policy_changed = !(from.ranking == to.ranking);
  diff.from_digest = from.digest;
  diff.to_digest = to.digest;

  std::map<ConstraintId, const Constraint*> left;
  for (const Constraint& constraint : from.constraints) {
    left.emplace(constraint.id, &constraint);
  }
  std::map<ConstraintId, const Constraint*> right;
  for (const Constraint& constraint : to.constraints) {
    right.emplace(constraint.id, &constraint);
  }
  for (const auto& entry : left) {
    const auto found = right.find(entry.first);
    if (found == right.end()) {
      diff.changes.push_back(ConstraintChange{ConstraintChangeKind::Removed, entry.first,
                                              entry.second->kind});
    } else if (!semantically_equal(*entry.second, *found->second)) {
      diff.changes.push_back(ConstraintChange{ConstraintChangeKind::Changed, entry.first,
                                              found->second->kind});
    }
  }
  for (const auto& entry : right) {
    if (left.find(entry.first) == left.end()) {
      diff.changes.push_back(
          ConstraintChange{ConstraintChangeKind::Added, entry.first, entry.second->kind});
    }
  }
  std::sort(diff.changes.begin(), diff.changes.end(),
            [](const ConstraintChange& a, const ConstraintChange& b) {
              if (a.kind != b.kind) return a.kind < b.kind;
              if (a.constraint != b.constraint) return a.constraint < b.constraint;
              return a.constraint_kind < b.constraint_kind;
            });
  return diff;
}

void encode_constraint_set(ByteWriter& writer, const ConstraintSet& set) {
  writer.put_u64(set.id.value());
  writer.put_u64(set.generation.value());
  writer.put_u8(static_cast<std::uint8_t>(set.state));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_string(set.name);
  writer.put_u64(set.declared_tick);
  writer.put_u64(set.evidence.topology.value());
  writer.put_u64(set.evidence.link_state.value());
  writer.put_u64(set.evidence.capability.value());
  writer.put_u64(set.evidence.failure_domain.value());
  writer.put_u64(set.evidence.policy.value());
  writer.put_u64(set.evidence.planner.value());
  writer.put_u64(set.evidence.path_authority.value());
  writer.put_u64(set.evidence.max_evidence_age_ticks);
  encode_ranking_policy(writer, set.ranking);
  writer.put_u32(static_cast<std::uint32_t>(set.constraints.size()));
  for (const Constraint& constraint : set.constraints) {
    encode_constraint(writer, constraint);
  }
  writer.put_raw(std::span<const std::byte>(set.digest.data(), Digest256::kSize));
}

namespace {

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

}  // namespace

bool decode_constraint_set(ByteReader& reader, const Limits& limits, ConstraintSet& out) {
  std::uint64_t id = 0;
  std::uint64_t generation = 0;
  std::uint8_t state = 0;
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.u64(id) || !reader.u64(generation) || !reader.u8(state) || !reader.u8(padding8) ||
      !reader.u16(padding16) || !reader.u32(padding32)) {
    return false;
  }
  if (id == 0 || !ConstraintSetGeneration::is_representable(generation) || state == 0 || state > 7 ||
      padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  out.id = ConstraintSetId::from_value(id);
  out.generation = ConstraintSetGeneration::from_value(generation);
  out.state = static_cast<ConstraintSetState>(state);
  if (!reader.string(out.name) || out.name.size() > limits.max_name_bytes) {
    reader.fail();
    return false;
  }
  if (!reader.u64(out.declared_tick) ||
      !read_generation_field(reader, out.evidence.topology) ||
      !read_generation_field(reader, out.evidence.link_state) ||
      !read_generation_field(reader, out.evidence.capability) ||
      !read_generation_field(reader, out.evidence.failure_domain) ||
      !read_generation_field(reader, out.evidence.policy) ||
      !read_generation_field(reader, out.evidence.planner) ||
      !read_generation_field(reader, out.evidence.path_authority) ||
      !reader.u64(out.evidence.max_evidence_age_ticks)) {
    return false;
  }
  if (!decode_ranking_policy(reader, out.ranking)) {
    return false;
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
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes))) {
    return false;
  }
  out.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  if (!reader.ok()) {
    return false;
  }
  const Status status = verify_canonical_constraint_set(out, limits);
  if (!status.ok()) {
    reader.fail();
    return false;
  }
  return true;
}

}  // namespace crf
