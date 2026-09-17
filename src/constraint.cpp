// Constraint Routing Fabric -- typed constraint model implementation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/constraint.hpp"

#include <string>
#include <vector>

namespace crf {
namespace {

template <class Id>
[[nodiscard]] bool all_valid(const std::vector<Id>& values) noexcept {
  for (const Id& value : values) {
    if (!value.is_valid()) {
      return false;
    }
  }
  return true;
}

template <class Id>
[[nodiscard]] bool sorted_unique(const std::vector<Id>& values) noexcept {
  for (std::size_t index = 1; index < values.size(); ++index) {
    if (!(values[index - 1] < values[index])) {
      return false;
    }
  }
  return true;
}

template <class Id>
[[nodiscard]] bool list_within(const std::vector<Id>& values, std::uint32_t max_size) noexcept {
  return values.size() <= max_size;
}

[[nodiscard]] bool any_entity_list(const Constraint& value) noexcept {
  return !value.nodes.empty() || !value.links.empty() || !value.tiers.empty() || !value.sites.empty() ||
         !value.capabilities.empty() || !value.policies.empty();
}

[[nodiscard]] Status malformed(const std::string& detail) {
  return Status::failure(ErrorCode::Malformed, detail);
}

[[nodiscard]] Status invalid(const std::string& detail) {
  return Status::failure(ErrorCode::InvalidArgument, detail);
}

[[nodiscard]] bool is_forbidden_kind(ConstraintKind kind) noexcept {
  return kind == ConstraintKind::ForbiddenNode || kind == ConstraintKind::ForbiddenLink ||
         kind == ConstraintKind::ForbiddenTier || kind == ConstraintKind::ForbiddenSite ||
         kind == ConstraintKind::ForbiddenCapability ||
         kind == ConstraintKind::ForbiddenFailureDomainRelation;
}

template <class Id>
void feed_list(SemanticHasher& hasher, const std::vector<Id>& values) {
  hasher.put_u32(static_cast<std::uint32_t>(values.size()));
  for (const Id& value : values) {
    hasher.put_u64(value.value());
  }
}

template <class Id>
void write_list(ByteWriter& writer, const std::vector<Id>& values) {
  writer.put_u32(static_cast<std::uint32_t>(values.size()));
  for (const Id& value : values) {
    writer.put_u64(value.value());
  }
}

template <class Id>
[[nodiscard]] bool read_list(ByteReader& reader, std::uint32_t max_size, std::vector<Id>& out) {
  std::uint32_t count = 0;
  if (!reader.bounded_length(max_size, count)) {
    return false;
  }
  out.clear();
  out.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint64_t raw = 0;
    if (!reader.u64(raw)) {
      return false;
    }
    if (raw == 0) {
      reader.fail();
      return false;
    }
    out.push_back(Id::from_value(raw));
  }
  return true;
}

[[nodiscard]] bool enum_in_range(std::uint32_t raw, std::uint32_t maximum) noexcept {
  return raw >= 1 && raw <= maximum;
}

}  // namespace

bool operator==(const Constraint& a, const Constraint& b) {
  return a.id == b.id && a.generation == b.generation && equivalent_payload(a, b);
}

bool equivalent_payload(const Constraint& a, const Constraint& b) noexcept {
  return a.kind == b.kind && a.scope == b.scope && a.unknown_policy == b.unknown_policy &&
         a.bound == b.bound && a.latency_source == b.latency_source && a.domain_kind == b.domain_kind &&
         a.domain_relation == b.domain_relation && a.locality_domain == b.locality_domain &&
         a.isolation_class == b.isolation_class && a.nodes == b.nodes && a.links == b.links &&
         a.tiers == b.tiers && a.sites == b.sites && a.capabilities == b.capabilities &&
         a.policies == b.policies && a.preference_rank == b.preference_rank &&
         a.preference_weight == b.preference_weight;
}

namespace {

template <class Id>
[[nodiscard]] int compare_lists(const std::vector<Id>& a, const std::vector<Id>& b) noexcept {
  const std::size_t shared = a.size() < b.size() ? a.size() : b.size();
  for (std::size_t index = 0; index < shared; ++index) {
    if (a[index] < b[index]) {
      return -1;
    }
    if (b[index] < a[index]) {
      return 1;
    }
  }
  if (a.size() != b.size()) {
    return a.size() < b.size() ? -1 : 1;
  }
  return 0;
}

/// Field-by-field comparison used for the canonical constraint order. Payload
/// first, identity last, so insertion order is never observable.
[[nodiscard]] int compare_payload(const Constraint& a, const Constraint& b) noexcept {
  if (a.kind != b.kind) return a.kind < b.kind ? -1 : 1;
  if (a.scope != b.scope) return a.scope < b.scope ? -1 : 1;
  if (a.bound != b.bound) return a.bound < b.bound ? -1 : 1;
  if (a.latency_source != b.latency_source) return a.latency_source < b.latency_source ? -1 : 1;
  if (a.domain_kind != b.domain_kind) return a.domain_kind < b.domain_kind ? -1 : 1;
  if (a.domain_relation != b.domain_relation) return a.domain_relation < b.domain_relation ? -1 : 1;
  if (a.locality_domain != b.locality_domain) return a.locality_domain < b.locality_domain ? -1 : 1;
  if (a.isolation_class != b.isolation_class) return a.isolation_class < b.isolation_class ? -1 : 1;
  if (a.unknown_policy != b.unknown_policy) return a.unknown_policy < b.unknown_policy ? -1 : 1;
  if (a.preference_rank != b.preference_rank) return a.preference_rank < b.preference_rank ? -1 : 1;
  if (a.preference_weight != b.preference_weight) return a.preference_weight < b.preference_weight ? -1 : 1;
  int list_comparison = compare_lists(a.nodes, b.nodes);
  if (list_comparison == 0) list_comparison = compare_lists(a.links, b.links);
  if (list_comparison == 0) list_comparison = compare_lists(a.tiers, b.tiers);
  if (list_comparison == 0) list_comparison = compare_lists(a.sites, b.sites);
  if (list_comparison == 0) list_comparison = compare_lists(a.capabilities, b.capabilities);
  if (list_comparison == 0) list_comparison = compare_lists(a.policies, b.policies);
  return list_comparison;
}

}  // namespace

bool canonical_less(const Constraint& a, const Constraint& b) noexcept {
  const int payload = compare_payload(a, b);
  if (payload != 0) {
    return payload < 0;
  }
  if (a.id != b.id) {
    return a.id < b.id;
  }
  return a.generation < b.generation;
}

Status validate_constraint(const Constraint& constraint, const Limits& limits) {
  if (!constraint.id.is_valid()) {
    return invalid("constraint id must be non-zero");
  }
  if (!constraint.generation.is_valid()) {
    return invalid("constraint generation must be non-zero");
  }
  if (constraint.kind == ConstraintKind::Unset || static_cast<std::uint16_t>(constraint.kind) > 18u) {
    return Status::failure(ErrorCode::UnknownConstraintKind, "constraint kind is not a known kind");
  }
  if (constraint.scope != ConstraintScope::Mandatory && constraint.scope != ConstraintScope::Preference) {
    return malformed("constraint scope is not a known scope");
  }
  if (constraint.unknown_policy != UnknownPolicy::FailClosed &&
      constraint.unknown_policy != UnknownPolicy::PermitUnknownNegative) {
    return malformed("unknown-evidence policy is not a known policy");
  }
  if (constraint.unknown_policy == UnknownPolicy::PermitUnknownNegative &&
      is_positive_requirement(constraint.kind)) {
    return invalid("unknown evidence can never be permitted to satisfy a positive requirement");
  }

  if (!list_within(constraint.nodes, limits.max_entity_refs_per_constraint) ||
      !list_within(constraint.links, limits.max_entity_refs_per_constraint) ||
      !list_within(constraint.tiers, limits.max_entity_refs_per_constraint) ||
      !list_within(constraint.sites, limits.max_entity_refs_per_constraint) ||
      !list_within(constraint.capabilities, limits.max_entity_refs_per_constraint) ||
      !list_within(constraint.policies, limits.max_entity_refs_per_constraint)) {
    return Status::failure(ErrorCode::ResourceLimit, "constraint entity reference list exceeds the limit");
  }
  if (!all_valid(constraint.nodes) || !all_valid(constraint.links) || !all_valid(constraint.tiers) ||
      !all_valid(constraint.sites) || !all_valid(constraint.capabilities) ||
      !all_valid(constraint.policies)) {
    return invalid("constraint entity reference must be non-zero");
  }

  if (constraint.scope == ConstraintScope::Mandatory) {
    if (constraint.preference_rank != 0 || constraint.preference_weight != 0) {
      return malformed("mandatory constraint must not carry preference metadata");
    }
  } else {
    if (constraint.preference_weight == 0 || constraint.preference_weight > 1000) {
      return Status::failure(ErrorCode::InvalidNumericBound,
                             "preference weight must be within 1..1000");
    }
  }

  switch (constraint.kind) {
    case ConstraintKind::MaxLatency: {
      if (constraint.latency_source != LatencySource::PlannerCost &&
          constraint.latency_source != LatencySource::ObservedLatency) {
        return malformed("MaxLatency requires an explicit latency source");
      }
      if (constraint.bound <= 0 || constraint.bound > kMaxFixedPointBound) {
        return Status::failure(ErrorCode::InvalidNumericBound,
                               "MaxLatency bound must be a positive fixed-point value");
      }
      if (any_entity_list(constraint) || constraint.domain_kind != DomainKind::Unset ||
          constraint.domain_relation != DomainRelation::Unset || constraint.locality_domain.is_valid() ||
          constraint.isolation_class.is_valid()) {
        return malformed("MaxLatency must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::MinBandwidthCapability: {
      if (constraint.bound <= 0 || constraint.bound > kMaxFixedPointBound) {
        return Status::failure(ErrorCode::InvalidNumericBound,
                               "MinBandwidthCapability bound must be a positive bits-per-second value");
      }
      if (any_entity_list(constraint) || constraint.latency_source != LatencySource::Unset ||
          constraint.domain_kind != DomainKind::Unset ||
          constraint.domain_relation != DomainRelation::Unset || constraint.locality_domain.is_valid() ||
          constraint.isolation_class.is_valid()) {
        return malformed("MinBandwidthCapability must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::MaxHopCount: {
      if (constraint.bound <= 0 || constraint.bound > 65535) {
        return Status::failure(ErrorCode::InvalidNumericBound,
                               "MaxHopCount bound must be within 1..65535");
      }
      if (any_entity_list(constraint) || constraint.latency_source != LatencySource::Unset ||
          constraint.domain_kind != DomainKind::Unset ||
          constraint.domain_relation != DomainRelation::Unset || constraint.locality_domain.is_valid() ||
          constraint.isolation_class.is_valid()) {
        return malformed("MaxHopCount must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredNode:
    case ConstraintKind::ForbiddenNode: {
      if (constraint.nodes.empty() || !constraint.links.empty() || !constraint.tiers.empty() ||
          !constraint.sites.empty() || !constraint.capabilities.empty() || !constraint.policies.empty()) {
        return malformed("node constraint requires a node list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredLink:
    case ConstraintKind::ForbiddenLink: {
      if (constraint.links.empty() || !constraint.nodes.empty() || !constraint.tiers.empty() ||
          !constraint.sites.empty() || !constraint.capabilities.empty() || !constraint.policies.empty()) {
        return malformed("link constraint requires a link list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredTier:
    case ConstraintKind::ForbiddenTier: {
      if (constraint.tiers.empty() || !constraint.nodes.empty() || !constraint.links.empty() ||
          !constraint.sites.empty() || !constraint.capabilities.empty() || !constraint.policies.empty()) {
        return malformed("tier constraint requires a tier list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredSite:
    case ConstraintKind::ForbiddenSite: {
      if (constraint.sites.empty() || !constraint.nodes.empty() || !constraint.links.empty() ||
          !constraint.tiers.empty() || !constraint.capabilities.empty() || !constraint.policies.empty()) {
        return malformed("site constraint requires a site list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::LocalityScope: {
      const bool locality_kind = constraint.domain_kind == DomainKind::Rack ||
                                 constraint.domain_kind == DomainKind::Site ||
                                 constraint.domain_kind == DomainKind::PowerZone ||
                                 constraint.domain_kind == DomainKind::CoolingZone ||
                                 constraint.domain_kind == DomainKind::Plane;
      if (!locality_kind || !constraint.locality_domain.is_valid()) {
        return malformed("LocalityScope requires an authoritative locality domain and kind");
      }
      if (any_entity_list(constraint) || constraint.bound != 0 ||
          constraint.domain_relation != DomainRelation::Unset || constraint.isolation_class.is_valid() ||
          constraint.latency_source != LatencySource::Unset) {
        return malformed("LocalityScope must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::IsolationClass: {
      if (!constraint.isolation_class.is_valid()) {
        return malformed("IsolationClass requires an authoritative isolation class identity");
      }
      if (any_entity_list(constraint) || constraint.bound != 0 ||
          constraint.domain_kind != DomainKind::Unset ||
          constraint.domain_relation != DomainRelation::Unset || constraint.locality_domain.is_valid() ||
          constraint.latency_source != LatencySource::Unset) {
        return malformed("IsolationClass must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredCapability:
    case ConstraintKind::ForbiddenCapability: {
      if (constraint.capabilities.empty() || !constraint.nodes.empty() || !constraint.links.empty() ||
          !constraint.tiers.empty() || !constraint.sites.empty() || !constraint.policies.empty()) {
        return malformed("capability constraint requires a capability list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::RequiredFailureDomainRelation: {
      if (constraint.domain_kind == DomainKind::Unset || constraint.domain_relation != DomainRelation::Distinct) {
        return malformed("RequiredFailureDomainRelation requires a domain kind and the Distinct relation");
      }
      if (constraint.bound < 1 || constraint.bound > kMaxFixedPointBound) {
        return Status::failure(ErrorCode::InvalidNumericBound,
                               "failure-domain relation count must be at least one");
      }
      if (any_entity_list(constraint) || constraint.locality_domain.is_valid() ||
          constraint.isolation_class.is_valid() || constraint.latency_source != LatencySource::Unset) {
        return malformed("failure-domain relation must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::ForbiddenFailureDomainRelation: {
      if (constraint.domain_kind == DomainKind::Unset) {
        return malformed("ForbiddenFailureDomainRelation requires a domain kind");
      }
      if (constraint.domain_relation == DomainRelation::Shared) {
        if (constraint.bound != 0) {
          return malformed("a forbidden shared relation does not take a count");
        }
      } else if (constraint.domain_relation == DomainRelation::Distinct) {
        if (constraint.bound < 1) {
          return Status::failure(ErrorCode::InvalidNumericBound,
                                 "a forbidden distinct relation requires a count of at least one");
        }
      } else {
        return malformed("ForbiddenFailureDomainRelation requires an explicit relation");
      }
      if (any_entity_list(constraint) || constraint.locality_domain.is_valid() ||
          constraint.isolation_class.is_valid() || constraint.latency_source != LatencySource::Unset) {
        return malformed("failure-domain relation must not carry unrelated payload");
      }
      return Status::success();
    }
    case ConstraintKind::AdministrativePolicy: {
      if (constraint.policies.empty() || !constraint.nodes.empty() || !constraint.links.empty() ||
          !constraint.tiers.empty() || !constraint.sites.empty() || !constraint.capabilities.empty()) {
        return malformed("policy constraint requires a policy list and nothing else");
      }
      return Status::success();
    }
    case ConstraintKind::Unset:
    default:
      return Status::failure(ErrorCode::UnknownConstraintKind, "constraint kind is not a known kind");
  }
}

bool semantically_equal(const Constraint& a, const Constraint& b) noexcept {
  return a == b;
}

std::vector<std::byte> encode_constraint_payload(const Constraint& constraint) {
  ByteWriter writer;
  writer.put_u16(static_cast<std::uint16_t>(constraint.kind));
  writer.put_u8(static_cast<std::uint8_t>(constraint.scope));
  writer.put_u8(static_cast<std::uint8_t>(constraint.unknown_policy));
  writer.put_i64(constraint.bound);
  writer.put_u8(static_cast<std::uint8_t>(constraint.latency_source));
  writer.put_u8(static_cast<std::uint8_t>(constraint.domain_kind));
  writer.put_u8(static_cast<std::uint8_t>(constraint.domain_relation));
  writer.put_u64(constraint.locality_domain.value());
  writer.put_u64(constraint.isolation_class.value());
  writer.put_u32(constraint.preference_rank);
  writer.put_u32(constraint.preference_weight);
  write_list(writer, constraint.nodes);
  write_list(writer, constraint.links);
  write_list(writer, constraint.tiers);
  write_list(writer, constraint.sites);
  write_list(writer, constraint.capabilities);
  write_list(writer, constraint.policies);
  return writer.buffer();
}

void feed_digest(SemanticHasher& hasher, const Constraint& constraint) {
  hasher.put_u64(constraint.id.value());
  hasher.put_u64(constraint.generation.value());
  hasher.put_u16(static_cast<std::uint16_t>(constraint.kind));
  hasher.put_u8(static_cast<std::uint8_t>(constraint.scope));
  hasher.put_u8(static_cast<std::uint8_t>(constraint.unknown_policy));
  hasher.put_i64(constraint.bound);
  hasher.put_u8(static_cast<std::uint8_t>(constraint.latency_source));
  hasher.put_u8(static_cast<std::uint8_t>(constraint.domain_kind));
  hasher.put_u8(static_cast<std::uint8_t>(constraint.domain_relation));
  hasher.put_u64(constraint.locality_domain.value());
  hasher.put_u64(constraint.isolation_class.value());
  hasher.put_u32(constraint.preference_rank);
  hasher.put_u32(constraint.preference_weight);
  feed_list(hasher, constraint.nodes);
  feed_list(hasher, constraint.links);
  feed_list(hasher, constraint.tiers);
  feed_list(hasher, constraint.sites);
  feed_list(hasher, constraint.capabilities);
  feed_list(hasher, constraint.policies);
}

void encode_constraint(ByteWriter& writer, const Constraint& constraint) {
  writer.put_u64(constraint.id.value());
  writer.put_u64(constraint.generation.value());
  writer.put_u16(static_cast<std::uint16_t>(constraint.kind));
  writer.put_u8(static_cast<std::uint8_t>(constraint.scope));
  writer.put_u8(static_cast<std::uint8_t>(constraint.unknown_policy));
  writer.put_i64(constraint.bound);
  writer.put_u8(static_cast<std::uint8_t>(constraint.latency_source));
  writer.put_u8(static_cast<std::uint8_t>(constraint.domain_kind));
  writer.put_u8(static_cast<std::uint8_t>(constraint.domain_relation));
  writer.put_u8(0);
  writer.put_u64(constraint.locality_domain.value());
  writer.put_u64(constraint.isolation_class.value());
  writer.put_u32(constraint.preference_rank);
  writer.put_u32(constraint.preference_weight);
  write_list(writer, constraint.nodes);
  write_list(writer, constraint.links);
  write_list(writer, constraint.tiers);
  write_list(writer, constraint.sites);
  write_list(writer, constraint.capabilities);
  write_list(writer, constraint.policies);
}

bool decode_constraint(ByteReader& reader, const Limits& limits, Constraint& out) {
  std::uint64_t id_raw = 0;
  std::uint64_t generation_raw = 0;
  std::uint16_t kind_raw = 0;
  std::uint8_t scope_raw = 0;
  std::uint8_t unknown_raw = 0;
  std::uint8_t latency_raw = 0;
  std::uint8_t domain_kind_raw = 0;
  std::uint8_t relation_raw = 0;
  std::uint8_t reserved = 0;
  std::uint64_t locality_raw = 0;
  std::uint64_t isolation_raw = 0;
  std::uint32_t rank_raw = 0;
  std::uint32_t weight_raw = 0;

  if (!reader.u64(id_raw) || !reader.u64(generation_raw) || !reader.u16(kind_raw) ||
      !reader.u8(scope_raw) || !reader.u8(unknown_raw) || !reader.i64(out.bound) ||
      !reader.u8(latency_raw) || !reader.u8(domain_kind_raw) || !reader.u8(relation_raw) ||
      !reader.u8(reserved) || !reader.u64(locality_raw) || !reader.u64(isolation_raw) ||
      !reader.u32(rank_raw) || !reader.u32(weight_raw)) {
    return false;
  }
  if (id_raw == 0 || !Generation<ConstraintGenerationTag>::is_representable(generation_raw) ||
      reserved != 0 || !enum_in_range(kind_raw, 18) || !enum_in_range(scope_raw, 2) ||
      !enum_in_range(unknown_raw, 2) || latency_raw > 2 || domain_kind_raw > 7 || relation_raw > 2) {
    reader.fail();
    return false;
  }
  if (!read_list(reader, limits.max_entity_refs_per_constraint, out.nodes) ||
      !read_list(reader, limits.max_entity_refs_per_constraint, out.links) ||
      !read_list(reader, limits.max_entity_refs_per_constraint, out.tiers) ||
      !read_list(reader, limits.max_entity_refs_per_constraint, out.sites) ||
      !read_list(reader, limits.max_entity_refs_per_constraint, out.capabilities) ||
      !read_list(reader, limits.max_entity_refs_per_constraint, out.policies)) {
    return false;
  }

  out.id = ConstraintId::from_value(id_raw);
  out.generation = ConstraintGeneration::from_value(generation_raw);
  out.kind = static_cast<ConstraintKind>(kind_raw);
  out.scope = static_cast<ConstraintScope>(scope_raw);
  out.unknown_policy = static_cast<UnknownPolicy>(unknown_raw);
  out.latency_source = static_cast<LatencySource>(latency_raw);
  out.domain_kind = static_cast<DomainKind>(domain_kind_raw);
  out.domain_relation = static_cast<DomainRelation>(relation_raw);
  out.locality_domain = LocalityDomainId::from_value(locality_raw);
  out.isolation_class = IsolationClassId::from_value(isolation_raw);
  out.preference_rank = rank_raw;
  out.preference_weight = weight_raw;

  // A decoded constraint must already be canonical: entity lists strictly
  // ascending. Non-canonical durable content is corruption, not a hint.
  if (!sorted_unique(out.nodes) || !sorted_unique(out.links) || !sorted_unique(out.tiers) ||
      !sorted_unique(out.sites) || !sorted_unique(out.capabilities) || !sorted_unique(out.policies)) {
    reader.fail();
    return false;
  }
  const Status status = validate_constraint(out, limits);
  if (!status.ok()) {
    reader.fail();
    return false;
  }
  return true;
}

const char* to_string(ConstraintKind kind) noexcept {
  switch (kind) {
    case ConstraintKind::Unset: return "Unset";
    case ConstraintKind::MaxLatency: return "MaxLatency";
    case ConstraintKind::MinBandwidthCapability: return "MinBandwidthCapability";
    case ConstraintKind::RequiredNode: return "RequiredNode";
    case ConstraintKind::ForbiddenNode: return "ForbiddenNode";
    case ConstraintKind::RequiredLink: return "RequiredLink";
    case ConstraintKind::ForbiddenLink: return "ForbiddenLink";
    case ConstraintKind::RequiredTier: return "RequiredTier";
    case ConstraintKind::ForbiddenTier: return "ForbiddenTier";
    case ConstraintKind::RequiredSite: return "RequiredSite";
    case ConstraintKind::ForbiddenSite: return "ForbiddenSite";
    case ConstraintKind::LocalityScope: return "LocalityScope";
    case ConstraintKind::IsolationClass: return "IsolationClass";
    case ConstraintKind::RequiredCapability: return "RequiredCapability";
    case ConstraintKind::ForbiddenCapability: return "ForbiddenCapability";
    case ConstraintKind::RequiredFailureDomainRelation: return "RequiredFailureDomainRelation";
    case ConstraintKind::ForbiddenFailureDomainRelation: return "ForbiddenFailureDomainRelation";
    case ConstraintKind::AdministrativePolicy: return "AdministrativePolicy";
    case ConstraintKind::MaxHopCount: return "MaxHopCount";
  }
  return "Unknown";
}

const char* to_string(ConstraintScope scope) noexcept {
  switch (scope) {
    case ConstraintScope::Mandatory: return "Mandatory";
    case ConstraintScope::Preference: return "Preference";
  }
  return "Unknown";
}

const char* to_string(LatencySource source) noexcept {
  switch (source) {
    case LatencySource::Unset: return "Unset";
    case LatencySource::PlannerCost: return "PlannerCost";
    case LatencySource::ObservedLatency: return "ObservedLatency";
  }
  return "Unknown";
}

const char* to_string(DomainKind kind) noexcept {
  switch (kind) {
    case DomainKind::Unset: return "Unset";
    case DomainKind::Node: return "Node";
    case DomainKind::Rack: return "Rack";
    case DomainKind::Site: return "Site";
    case DomainKind::PowerZone: return "PowerZone";
    case DomainKind::CoolingZone: return "CoolingZone";
    case DomainKind::Plane: return "Plane";
    case DomainKind::FailureDomain: return "FailureDomain";
  }
  return "Unknown";
}

const char* to_string(DomainRelation relation) noexcept {
  switch (relation) {
    case DomainRelation::Unset: return "Unset";
    case DomainRelation::Distinct: return "Distinct";
    case DomainRelation::Shared: return "Shared";
  }
  return "Unknown";
}

const char* to_string(UnknownPolicy policy) noexcept {
  switch (policy) {
    case UnknownPolicy::FailClosed: return "FailClosed";
    case UnknownPolicy::PermitUnknownNegative: return "PermitUnknownNegative";
  }
  return "Unknown";
}

const char* to_string(EvidenceProvenance provenance) noexcept {
  switch (provenance) {
    case EvidenceProvenance::None: return "None";
    case EvidenceProvenance::FabricCapabilityRegistry: return "FabricCapabilityRegistry";
    case EvidenceProvenance::FabricTopologyAuthority: return "FabricTopologyAuthority";
    case EvidenceProvenance::FabricLinkStateAuthority: return "FabricLinkStateAuthority";
    case EvidenceProvenance::FabricFailureDomainAuthority: return "FabricFailureDomainAuthority";
    case EvidenceProvenance::FabricPolicyRegistry: return "FabricPolicyRegistry";
    case EvidenceProvenance::PlannerModel: return "PlannerModel";
    case EvidenceProvenance::SyntheticFixture: return "SyntheticFixture";
    case EvidenceProvenance::OperatorDeclaration: return "OperatorDeclaration";
  }
  return "Unknown";
}

const char* to_string(CapabilityModel model) noexcept {
  switch (model) {
    case CapabilityModel::None: return "None";
    case CapabilityModel::DeclaredCapabilityRegistry: return "DeclaredCapabilityRegistry";
    case CapabilityModel::SyntheticFixture: return "SyntheticFixture";
  }
  return "Unknown";
}

const char* to_string(PlannerCostModel model) noexcept {
  switch (model) {
    case PlannerCostModel::None: return "None";
    case PlannerCostModel::HopCountUnits: return "HopCountUnits";
    case PlannerCostModel::ModelledLatencyMicros: return "ModelledLatencyMicros";
    case PlannerCostModel::AdministrativeMetric: return "AdministrativeMetric";
  }
  return "Unknown";
}

const char* to_string(EvidenceFamily family) noexcept {
  switch (family) {
    case EvidenceFamily::None: return "None";
    case EvidenceFamily::ConstraintSet: return "ConstraintSet";
    case EvidenceFamily::Topology: return "Topology";
    case EvidenceFamily::LinkState: return "LinkState";
    case EvidenceFamily::Capability: return "Capability";
    case EvidenceFamily::FailureDomain: return "FailureDomain";
    case EvidenceFamily::Policy: return "Policy";
    case EvidenceFamily::Planner: return "Planner";
    case EvidenceFamily::PathAuthority: return "PathAuthority";
  }
  return "Unknown";
}

EvidenceFamilyMask evidence_families(ConstraintKind kind) noexcept {
  switch (kind) {
    case ConstraintKind::MaxLatency:
      // Modelled latency binds the planner model; observed latency binds the
      // link-state evidence that carried the observation. They never mix.
      return family_bit(EvidenceFamily::Planner) | family_bit(EvidenceFamily::LinkState);
    case ConstraintKind::MinBandwidthCapability:
    case ConstraintKind::RequiredCapability:
    case ConstraintKind::ForbiddenCapability:
      return family_bit(EvidenceFamily::Capability);
    case ConstraintKind::RequiredNode:
    case ConstraintKind::ForbiddenNode:
    case ConstraintKind::RequiredLink:
    case ConstraintKind::ForbiddenLink:
    case ConstraintKind::RequiredTier:
    case ConstraintKind::ForbiddenTier:
    case ConstraintKind::RequiredSite:
    case ConstraintKind::ForbiddenSite:
    case ConstraintKind::LocalityScope:
      return family_bit(EvidenceFamily::Topology);
    case ConstraintKind::IsolationClass:
    case ConstraintKind::RequiredFailureDomainRelation:
    case ConstraintKind::ForbiddenFailureDomainRelation:
      return family_bit(EvidenceFamily::FailureDomain);
    case ConstraintKind::AdministrativePolicy:
      return family_bit(EvidenceFamily::Policy);
    case ConstraintKind::MaxHopCount:
      return family_bit(EvidenceFamily::Planner);
    case ConstraintKind::Unset:
    default:
      return 0;
  }
}

}  // namespace crf
