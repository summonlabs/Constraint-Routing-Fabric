// Constraint Routing Fabric -- precise invalidation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/invalidation.hpp"

#include <algorithm>
#include <set>
#include <string>

namespace crf {
namespace {

[[nodiscard]] std::uint64_t generation_for_family(const EvidenceGenerationSet& evidence,
                                                  EvidenceFamily family) noexcept {
  switch (family) {
    case EvidenceFamily::Topology: return evidence.topology.value();
    case EvidenceFamily::LinkState: return evidence.link_state.value();
    case EvidenceFamily::Capability: return evidence.capability.value();
    case EvidenceFamily::FailureDomain: return evidence.failure_domain.value();
    case EvidenceFamily::Policy: return evidence.policy.value();
    case EvidenceFamily::Planner: return evidence.planner.value();
    case EvidenceFamily::PathAuthority: return evidence.path_authority.value();
    default: return 0;
  }
}

void add(InvalidationIndex& index, const InvalidationKey& key, const ConstraintEvaluationId& id,
         Status& status) {
  if (!status.ok()) {
    return;
  }
  const Status bound = index.bind(key, id);
  if (!bound.ok()) {
    status = bound;
  }
}

bool family_consulted(const EvaluationRecord& record, EvidenceFamily family) noexcept {
  return (record.consulted & family_bit(family)) != 0;
}

}  // namespace

const char* to_string(InvalidationKeyKind kind) noexcept {
  switch (kind) {
    case InvalidationKeyKind::ConstraintSet: return "ConstraintSet";
    case InvalidationKeyKind::Path: return "Path";
    case InvalidationKeyKind::Node: return "Node";
    case InvalidationKeyKind::Link: return "Link";
    case InvalidationKeyKind::Capability: return "Capability";
    case InvalidationKeyKind::Policy: return "Policy";
    case InvalidationKeyKind::FailureDomain: return "FailureDomain";
    case InvalidationKeyKind::LocalityDomain: return "LocalityDomain";
    case InvalidationKeyKind::IsolationClass: return "IsolationClass";
    case InvalidationKeyKind::Planner: return "Planner";
    case InvalidationKeyKind::Topology: return "Topology";
    case InvalidationKeyKind::LinkState: return "LinkState";
    case InvalidationKeyKind::PathAuthority: return "PathAuthority";
  }
  return "Unknown";
}

std::uint64_t Watermarks::family(EvidenceFamily family) const noexcept {
  const auto found = families_.find(family);
  return found == families_.end() ? 0 : found->second;
}

bool Watermarks::advance_family(EvidenceFamily family, std::uint64_t generation) noexcept {
  const auto found = families_.find(family);
  if (found != families_.end() && generation <= found->second) {
    return false;
  }
  families_[family] = generation;
  return true;
}

std::uint64_t Watermarks::key(const InvalidationKey& key) const noexcept {
  const auto found = keys_.find(key);
  return found == keys_.end() ? 0 : found->second;
}

bool Watermarks::advance_key(const InvalidationKey& key, std::uint64_t watermark) noexcept {
  const auto found = keys_.find(key);
  if (found != keys_.end() && watermark <= found->second) {
    return false;
  }
  keys_[key] = watermark;
  return true;
}

void Watermarks::clear() noexcept {
  families_.clear();
  keys_.clear();
}

Status InvalidationIndex::bind(const InvalidationKey& key, const ConstraintEvaluationId& evaluation) {
  if (!evaluation.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "invalidation binding requires an evaluation id");
  }
  forward_[key].insert(evaluation);
  reverse_[evaluation].insert(key);
  return Status::success();
}

Status InvalidationIndex::unbind(const ConstraintEvaluationId& evaluation) {
  const auto found = reverse_.find(evaluation);
  if (found == reverse_.end()) {
    return Status::success();
  }
  for (const InvalidationKey& key : found->second) {
    const auto entry = forward_.find(key);
    if (entry != forward_.end()) {
      entry->second.erase(evaluation);
      if (entry->second.empty()) {
        forward_.erase(entry);
      }
    }
  }
  reverse_.erase(found);
  return Status::success();
}

std::vector<ConstraintEvaluationId> InvalidationIndex::dependents(
    const InvalidationKey& key) const {
  std::vector<ConstraintEvaluationId> out;
  const auto found = forward_.find(key);
  if (found == forward_.end()) {
    return out;
  }
  out.assign(found->second.begin(), found->second.end());
  return out;
}

std::vector<InvalidationKey> InvalidationIndex::keys_of_kinds(
    std::span<const InvalidationKeyKind> kinds) const {
  std::vector<InvalidationKey> out;
  for (const auto& entry : forward_) {
    for (const InvalidationKeyKind kind : kinds) {
      if (entry.first.kind == kind) {
        out.push_back(entry.first);
        break;
      }
    }
  }
  return out;
}

bool InvalidationIndex::is_bound(const ConstraintEvaluationId& evaluation) const noexcept {
  return reverse_.find(evaluation) != reverse_.end();
}

void InvalidationIndex::clear() {
  forward_.clear();
  reverse_.clear();
}

Status InvalidationIndex::validate() const {
  for (const auto& entry : forward_) {
    for (const ConstraintEvaluationId& evaluation : entry.second) {
      const auto reverse_entry = reverse_.find(evaluation);
      if (reverse_entry == reverse_.end() || reverse_entry->second.count(entry.first) == 0) {
        return Status::failure(ErrorCode::Internal,
                               "invalidation index forward entry has no reverse entry");
      }
    }
  }
  for (const auto& entry : reverse_) {
    if (entry.second.empty()) {
      return Status::failure(ErrorCode::Internal,
                             "invalidation index reverse entry has no dependency keys");
    }
    for (const InvalidationKey& key : entry.second) {
      const auto forward_entry = forward_.find(key);
      if (forward_entry == forward_.end() || forward_entry->second.count(entry.first) == 0) {
        return Status::failure(ErrorCode::Internal,
                               "invalidation index reverse entry has no forward entry");
      }
    }
  }
  return Status::success();
}

Status InvalidationIndex::check_limits(const Limits& limits) const {
  if (forward_.size() > limits.max_decoded_count) {
    return Status::failure(ErrorCode::ResourceLimit, "invalidation index key count exceeds the limit");
  }
  if (reverse_.size() > limits.max_evaluations_retained) {
    return Status::failure(ErrorCode::ResourceLimit,
                           "invalidation index evaluation count exceeds the retention limit");
  }
  return Status::success();
}

std::vector<InvalidationKey> dependency_keys(const EvaluationRecord& record, const ConstraintSet& set,
                                             const CandidatePath& candidate, const Limits& limits) {
  (void)limits;
  std::set<InvalidationKey> keys;
  keys.insert(InvalidationKey{InvalidationKeyKind::ConstraintSet, set.id.value()});
  keys.insert(InvalidationKey{InvalidationKeyKind::Path, candidate.path.value()});

  if (family_consulted(record, EvidenceFamily::Topology)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::Topology, 0});
    for (const NodeFact& node : candidate.nodes) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Node, node.node.value()});
      for (const LocalityRef& locality : node.localities) {
        keys.insert(InvalidationKey{InvalidationKeyKind::LocalityDomain, locality.domain.value()});
      }
    }
    for (const LinkFact& link : candidate.links) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Link, link.link.value()});
    }
  }
  if (family_consulted(record, EvidenceFamily::Capability)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::Capability, 0});
    for (const Constraint& constraint : set.constraints) {
      for (const CapabilityId& capability : constraint.capabilities) {
        keys.insert(InvalidationKey{InvalidationKeyKind::Capability, capability.value()});
      }
    }
    for (const NodeFact& node : candidate.nodes) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Node, node.node.value()});
      for (const CapabilityRef& ref : node.capabilities) {
        keys.insert(InvalidationKey{InvalidationKeyKind::Capability, ref.capability.value()});
      }
    }
    for (const LinkFact& link : candidate.links) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Link, link.link.value()});
      for (const CapabilityRef& ref : link.capabilities) {
        keys.insert(InvalidationKey{InvalidationKeyKind::Capability, ref.capability.value()});
      }
    }
  }
  if (family_consulted(record, EvidenceFamily::FailureDomain)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::FailureDomain, 0});
    for (const NodeFact& node : candidate.nodes) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Node, node.node.value()});
      for (const FailureDomainRef& ref : node.domains) {
        keys.insert(InvalidationKey{InvalidationKeyKind::FailureDomain, ref.domain.value()});
      }
      for (const IsolationAttestation& ref : node.isolation) {
        keys.insert(InvalidationKey{InvalidationKeyKind::IsolationClass, ref.isolation_class.value()});
      }
    }
    for (const LinkFact& link : candidate.links) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Link, link.link.value()});
      for (const FailureDomainRef& ref : link.domains) {
        keys.insert(InvalidationKey{InvalidationKeyKind::FailureDomain, ref.domain.value()});
      }
      for (const IsolationAttestation& ref : link.isolation) {
        keys.insert(InvalidationKey{InvalidationKeyKind::IsolationClass, ref.isolation_class.value()});
      }
    }
  }
  if (family_consulted(record, EvidenceFamily::Policy)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::Policy, 0});
    for (const PolicyAttestation& ref : candidate.policies) {
      keys.insert(InvalidationKey{InvalidationKeyKind::Policy, ref.policy.value()});
    }
  }
  if (family_consulted(record, EvidenceFamily::Planner)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::Planner, 0});
  }
  if (family_consulted(record, EvidenceFamily::LinkState)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::LinkState, 0});
  }
  if (family_consulted(record, EvidenceFamily::PathAuthority)) {
    keys.insert(InvalidationKey{InvalidationKeyKind::PathAuthority, 0});
  }
  return std::vector<InvalidationKey>(keys.begin(), keys.end());
}

bool evaluation_current(const EvaluationRecord& record, const Watermarks& watermarks) noexcept {
  if (record.state != ResultState::Current) {
    return false;
  }
  const std::array<EvidenceFamily, 7> families = {
      EvidenceFamily::Topology,      EvidenceFamily::LinkState,     EvidenceFamily::Capability,
      EvidenceFamily::FailureDomain, EvidenceFamily::Policy,        EvidenceFamily::Planner,
      EvidenceFamily::PathAuthority};
  for (const EvidenceFamily family : families) {
    if (!family_consulted(record, family)) {
      continue;
    }
    const std::uint64_t observed = generation_for_family(record.evidence, family);
    if (watermarks.family(family) > observed) {
      return false;
    }
  }
  return true;
}

void encode_watermarks(ByteWriter& writer, const Watermarks& watermarks) {
  writer.put_u32(static_cast<std::uint32_t>(watermarks.keys().size()));
  for (const auto& entry : watermarks.keys()) {
    writer.put_u8(static_cast<std::uint8_t>(entry.first.kind));
    writer.put_u8(0);
    writer.put_u16(0);
    writer.put_u32(0);
    writer.put_u64(entry.first.value);
    writer.put_u64(entry.second);
  }
  writer.put_u32(7);
  const std::array<EvidenceFamily, 7> families = {
      EvidenceFamily::Topology,      EvidenceFamily::LinkState,     EvidenceFamily::Capability,
      EvidenceFamily::FailureDomain, EvidenceFamily::Policy,        EvidenceFamily::Planner,
      EvidenceFamily::PathAuthority};
  for (const EvidenceFamily family : families) {
    writer.put_u8(static_cast<std::uint8_t>(family));
    writer.put_u8(0);
    writer.put_u16(0);
    writer.put_u32(0);
    writer.put_u64(watermarks.family(family));
  }
}

bool decode_watermarks(ByteReader& reader, const Limits& limits, Watermarks& out) {
  out.clear();
  std::uint32_t key_count = 0;
  if (!reader.bounded_length(limits.max_decoded_count, key_count)) {
    return false;
  }
  InvalidationKey previous{};
  bool has_previous = false;
  for (std::uint32_t index = 0; index < key_count; ++index) {
    std::uint8_t kind = 0;
    std::uint8_t padding8 = 0;
    std::uint16_t padding16 = 0;
    std::uint32_t padding32 = 0;
    std::uint64_t value = 0;
    std::uint64_t watermark = 0;
    if (!reader.u8(kind) || !reader.u8(padding8) || !reader.u16(padding16) || !reader.u32(padding32) ||
        !reader.u64(value) || !reader.u64(watermark)) {
      return false;
    }
    if (kind == 0 || kind > 13 || padding8 != 0 || padding16 != 0 || padding32 != 0) {
      reader.fail();
      return false;
    }
    const InvalidationKey key{static_cast<InvalidationKeyKind>(kind), value};
    if (has_previous && !(previous < key)) {
      reader.fail();
      return false;
    }
    previous = key;
    has_previous = true;
    (void)out.advance_key(key, watermark);
  }
  std::uint32_t family_count = 0;
  if (!reader.bounded_length(16, family_count) || family_count != 7) {
    reader.fail();
    return false;
  }
  for (std::uint32_t index = 0; index < family_count; ++index) {
    std::uint8_t family = 0;
    std::uint8_t padding8 = 0;
    std::uint16_t padding16 = 0;
    std::uint32_t padding32 = 0;
    std::uint64_t watermark = 0;
    if (!reader.u8(family) || !reader.u8(padding8) || !reader.u16(padding16) || !reader.u32(padding32) ||
        !reader.u64(watermark)) {
      return false;
    }
    if (family == 0 || family > 8 || padding8 != 0 || padding16 != 0 || padding32 != 0) {
      reader.fail();
      return false;
    }
    (void)out.advance_family(static_cast<EvidenceFamily>(family), watermark);
  }
  return true;
}

}  // namespace crf
