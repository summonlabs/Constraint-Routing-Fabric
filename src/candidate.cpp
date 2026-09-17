// Constraint Routing Fabric -- candidates and authoritative evidence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/candidate.hpp"

#include <algorithm>
#include <array>
#include <string>

namespace crf {
namespace {

[[nodiscard]] Status malformed(const std::string& detail) {
  return Status::failure(ErrorCode::Malformed, detail);
}

template <class Ref>
[[nodiscard]] bool sorted_unique(const std::vector<Ref>& values) {
  for (std::size_t index = 1; index < values.size(); ++index) {
    if (!(values[index - 1] < values[index])) {
      return false;
    }
  }
  return true;
}

/// Sorts and de-duplicates a reference list. Two entries that disagree about a
/// generation for the same identity are contradictory evidence and are refused
/// rather than silently reduced.
template <class Ref, class KeyFn>
[[nodiscard]] Status canonicalize_refs(std::vector<Ref>& values, KeyFn key, const char* what) {
  std::sort(values.begin(), values.end());
  std::vector<Ref> canonical;
  canonical.reserve(values.size());
  for (const Ref& value : values) {
    if (!canonical.empty() && canonical.back() == value) {
      continue;
    }
    if (!canonical.empty() && key(canonical.back()) == key(value)) {
      return malformed(std::string("contradictory ") + what + " evidence: same identity, different generation");
    }
    canonical.push_back(value);
  }
  values = std::move(canonical);
  return Status::success();
}

[[nodiscard]] Status canonicalize_node(NodeFact& node, const Limits& limits) {
  if (node.localities.size() > limits.max_localities_per_entity) {
    return Status::failure(ErrorCode::ResourceLimit, "node locality membership exceeds the limit");
  }
  if (node.domains.size() > limits.max_domains_per_entity) {
    return Status::failure(ErrorCode::ResourceLimit, "node failure-domain membership exceeds the limit");
  }
  if (node.capabilities.size() > limits.max_capabilities_per_entity) {
    return Status::failure(ErrorCode::ResourceLimit, "node capability evidence exceeds the limit");
  }
  std::sort(node.localities.begin(), node.localities.end());
  node.localities.erase(std::unique(node.localities.begin(), node.localities.end()), node.localities.end());
  std::sort(node.domains.begin(), node.domains.end());
  node.domains.erase(std::unique(node.domains.begin(), node.domains.end()), node.domains.end());
  std::sort(node.isolation.begin(), node.isolation.end());
  node.isolation.erase(std::unique(node.isolation.begin(), node.isolation.end()), node.isolation.end());
  return canonicalize_refs(node.capabilities, [](const CapabilityRef& ref) { return ref.capability; },
                           "capability");
}

[[nodiscard]] Status canonicalize_link(LinkFact& link, const Limits& limits) {
  if (link.domains.size() > limits.max_domains_per_entity) {
    return Status::failure(ErrorCode::ResourceLimit, "link failure-domain membership exceeds the limit");
  }
  if (link.capabilities.size() > limits.max_capabilities_per_entity) {
    return Status::failure(ErrorCode::ResourceLimit, "link capability evidence exceeds the limit");
  }
  std::sort(link.domains.begin(), link.domains.end());
  link.domains.erase(std::unique(link.domains.begin(), link.domains.end()), link.domains.end());
  std::sort(link.isolation.begin(), link.isolation.end());
  link.isolation.erase(std::unique(link.isolation.begin(), link.isolation.end()), link.isolation.end());
  return canonicalize_refs(link.capabilities, [](const CapabilityRef& ref) { return ref.capability; },
                           "capability");
}

[[nodiscard]] bool same_endpoints(const LinkFact& link, NodeId a, NodeId b) noexcept {
  return (link.endpoints[0] == a && link.endpoints[1] == b) ||
         (link.endpoints[0] == b && link.endpoints[1] == a);
}

void feed_locality(SemanticHasher& hasher, const LocalityRef& ref) {
  hasher.put_u8(static_cast<std::uint8_t>(ref.kind));
  hasher.put_u64(ref.domain.value());
}

void feed_domain(SemanticHasher& hasher, const FailureDomainRef& ref) {
  hasher.put_u8(static_cast<std::uint8_t>(ref.kind));
  hasher.put_u64(ref.domain.value());
}

void feed_capability(SemanticHasher& hasher, const CapabilityRef& ref) {
  hasher.put_u64(ref.capability.value());
  hasher.put_u64(ref.generation.value());
}

void feed_isolation(SemanticHasher& hasher, const IsolationAttestation& ref) {
  hasher.put_u64(ref.isolation_class.value());
  hasher.put_u64(ref.generation.value());
}

void write_locality(ByteWriter& writer, const LocalityRef& ref) {
  writer.put_u8(static_cast<std::uint8_t>(ref.kind));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u64(ref.domain.value());
}

[[nodiscard]] bool read_locality(ByteReader& reader, LocalityRef& out) {
  std::uint8_t kind = 0;
  std::uint8_t padding = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  std::uint64_t domain = 0;
  if (!reader.u8(kind) || !reader.u8(padding) || !reader.u16(padding16) || !reader.u32(padding32) ||
      !reader.u64(domain)) {
    return false;
  }
  if (padding != 0 || padding16 != 0 || padding32 != 0 || kind == 0 || kind > 7) {
    reader.fail();
    return false;
  }
  out.kind = static_cast<DomainKind>(kind);
  out.domain = LocalityDomainId::from_value(domain);
  return domain != 0;
}

void write_domain(ByteWriter& writer, const FailureDomainRef& ref) {
  writer.put_u8(static_cast<std::uint8_t>(ref.kind));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u64(ref.domain.value());
}

[[nodiscard]] bool read_domain(ByteReader& reader, FailureDomainRef& out) {
  std::uint8_t kind = 0;
  std::uint8_t padding = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  std::uint64_t domain = 0;
  if (!reader.u8(kind) || !reader.u8(padding) || !reader.u16(padding16) || !reader.u32(padding32) ||
      !reader.u64(domain)) {
    return false;
  }
  if (padding != 0 || padding16 != 0 || padding32 != 0 || kind == 0 || kind > 7) {
    reader.fail();
    return false;
  }
  out.kind = static_cast<DomainKind>(kind);
  out.domain = FailureDomainId::from_value(domain);
  return domain != 0;
}

void write_capability(ByteWriter& writer, const CapabilityRef& ref) {
  writer.put_u64(ref.capability.value());
  writer.put_u64(ref.generation.value());
}

[[nodiscard]] bool read_capability(ByteReader& reader, CapabilityRef& out) {
  std::uint64_t capability = 0;
  std::uint64_t generation = 0;
  if (!reader.u64(capability) || !reader.u64(generation)) {
    return false;
  }
  if (capability == 0 || !CapabilityGeneration::is_representable(generation)) {
    reader.fail();
    return false;
  }
  out.capability = CapabilityId::from_value(capability);
  out.generation = CapabilityGeneration::from_value(generation);
  return true;
}

void write_isolation(ByteWriter& writer, const IsolationAttestation& ref) {
  writer.put_u64(ref.isolation_class.value());
  writer.put_u64(ref.generation.value());
}

[[nodiscard]] bool read_isolation(ByteReader& reader, IsolationAttestation& out) {
  std::uint64_t isolation_class = 0;
  std::uint64_t generation = 0;
  if (!reader.u64(isolation_class) || !reader.u64(generation)) {
    return false;
  }
  if (isolation_class == 0 || !FailureDomainGeneration::is_representable(generation)) {
    reader.fail();
    return false;
  }
  out.isolation_class = IsolationClassId::from_value(isolation_class);
  out.generation = FailureDomainGeneration::from_value(generation);
  return true;
}

void feed_evidence(SemanticHasher& hasher, const EvidenceGenerationSet& evidence) {
  hasher.put_u64(evidence.topology.value());
  hasher.put_u64(evidence.link_state.value());
  hasher.put_u64(evidence.capability.value());
  hasher.put_u64(evidence.failure_domain.value());
  hasher.put_u64(evidence.policy.value());
  hasher.put_u64(evidence.planner.value());
  hasher.put_u64(evidence.path_authority.value());
  hasher.put_u32(evidence.consulted);
}

}  // namespace

bool operator==(const LatencyEvidence& a, const LatencyEvidence& b) noexcept {
  return a.source == b.source && a.provenance == b.provenance && a.micros == b.micros &&
         a.planner_generation == b.planner_generation && a.observed_generation == b.observed_generation;
}

bool operator==(const BandwidthCapabilityEvidence& a, const BandwidthCapabilityEvidence& b) noexcept {
  return a.model == b.model && a.provenance == b.provenance && a.bits_per_second == b.bits_per_second &&
         a.generation == b.generation;
}

bool operator==(const EvidenceGenerationSet& a, const EvidenceGenerationSet& b) noexcept {
  return a.topology == b.topology && a.link_state == b.link_state && a.capability == b.capability &&
         a.failure_domain == b.failure_domain && a.policy == b.policy && a.planner == b.planner &&
         a.path_authority == b.path_authority && a.consulted == b.consulted;
}

Status validate_candidate(const CandidatePath& candidate, const Limits& limits) {
  if (!candidate.path.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "candidate path identity must be non-zero");
  }
  if (!candidate.authority_generation.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument,
                           "candidate must carry an exact Path Authority generation");
  }
  if (candidate.evidence.path_authority != candidate.authority_generation) {
    return malformed("candidate evidence binding disagrees with its Path Authority generation");
  }
  if (candidate.nodes.size() < 2) {
    return malformed("candidate must contain at least two nodes");
  }
  if (candidate.nodes.size() > limits.max_nodes_per_candidate) {
    return Status::failure(ErrorCode::ResourceLimit, "candidate node count exceeds the limit");
  }
  if (candidate.links.size() != candidate.nodes.size() - 1) {
    return malformed("candidate link count must be exactly one less than its node count");
  }
  if (candidate.links.size() > limits.max_links_per_candidate) {
    return Status::failure(ErrorCode::ResourceLimit, "candidate link count exceeds the limit");
  }
  if (candidate.hop_count != candidate.links.size()) {
    return malformed("candidate hop count must equal its link count");
  }
  if (candidate.policies.size() > limits.max_policies_per_candidate) {
    return Status::failure(ErrorCode::ResourceLimit, "candidate policy attestations exceed the limit");
  }
  for (std::size_t index = 0; index < candidate.nodes.size(); ++index) {
    const NodeFact& node = candidate.nodes[index];
    if (!node.node.is_valid()) {
      return Status::failure(ErrorCode::InvalidArgument, "candidate node identity must be non-zero");
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if (candidate.nodes[previous].node == node.node) {
        return malformed("candidate traversal repeats a node identity");
      }
    }
    if (node.localities.size() > limits.max_localities_per_entity ||
        node.domains.size() > limits.max_domains_per_entity ||
        node.capabilities.size() > limits.max_capabilities_per_entity) {
      return Status::failure(ErrorCode::ResourceLimit, "node evidence exceeds the configured limit");
    }
    if (!sorted_unique(node.localities) || !sorted_unique(node.domains) ||
        !sorted_unique(node.capabilities) || !sorted_unique(node.isolation)) {
      return malformed("node evidence vectors are not canonical");
    }
    for (const LocalityRef& ref : node.localities) {
      if (ref.kind == DomainKind::Unset || !ref.domain.is_valid()) {
        return malformed("locality membership must carry an authoritative kind and identity");
      }
    }
    for (const FailureDomainRef& ref : node.domains) {
      if (ref.kind == DomainKind::Unset || !ref.domain.is_valid()) {
        return malformed("failure-domain membership must carry an authoritative kind and identity");
      }
    }
  }
  for (std::size_t index = 0; index < candidate.links.size(); ++index) {
    const LinkFact& link = candidate.links[index];
    if (!link.link.is_valid()) {
      return Status::failure(ErrorCode::InvalidArgument, "candidate link identity must be non-zero");
    }
    if (!same_endpoints(link, candidate.nodes[index].node, candidate.nodes[index + 1].node)) {
      return malformed("candidate link endpoints do not match the consecutive nodes");
    }
    if (link.domains.size() > limits.max_domains_per_entity ||
        link.capabilities.size() > limits.max_capabilities_per_entity) {
      return Status::failure(ErrorCode::ResourceLimit, "link evidence exceeds the configured limit");
    }
    if (!sorted_unique(link.domains) || !sorted_unique(link.capabilities) ||
        !sorted_unique(link.isolation)) {
      return malformed("link evidence vectors are not canonical");
    }
    if (link.bandwidth.model != CapabilityModel::None &&
        (link.bandwidth.bits_per_second < 0 || !link.bandwidth.generation.is_valid())) {
      return malformed("link bandwidth capability evidence is not well formed");
    }
  }
  if (candidate.latency.source != LatencySource::Unset) {
    if (candidate.latency.micros < 0 || candidate.latency.micros > kMaxFixedPointBound) {
      return Status::failure(ErrorCode::InvalidNumericBound, "candidate latency evidence is out of range");
    }
    if (candidate.latency.source == LatencySource::PlannerCost &&
        !candidate.latency.planner_generation.is_valid()) {
      return malformed("modelled latency must bind an exact planner generation");
    }
    if (candidate.latency.source == LatencySource::ObservedLatency &&
        !candidate.latency.observed_generation.is_valid()) {
      return malformed("observed latency must bind an exact evidence generation");
    }
    // The latency figure's own generation must agree with the candidate's
    // evidence binding: a mismatched internal binding would let modelled and
    // measured latency be compared against the wrong generation.
    if (candidate.latency.source == LatencySource::PlannerCost &&
        candidate.latency.planner_generation != candidate.evidence.planner) {
      return malformed("modelled latency generation disagrees with the candidate evidence binding");
    }
    if (candidate.latency.source == LatencySource::ObservedLatency &&
        candidate.latency.observed_generation != candidate.evidence.link_state) {
      return malformed("observed latency generation disagrees with the candidate evidence binding");
    }
  }
  if (candidate.has_planner_cost && candidate.cost_model == PlannerCostModel::None) {
    return malformed("a planner cost must declare its cost model");
  }
  if (!candidate.has_planner_cost && candidate.cost_model != PlannerCostModel::None) {
    return malformed("a cost model without a planner cost is ambiguous");
  }
  if (!sorted_unique(candidate.policies)) {
    return malformed("candidate policy attestations are not canonical");
  }
  return Status::success();
}

Status canonicalize_candidate(CandidatePath& candidate, const Limits& limits) {
  if (!candidate.path.is_valid() || !candidate.authority_generation.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "candidate identity must be non-zero");
  }
  if (candidate.nodes.size() < 2 || candidate.nodes.size() > limits.max_nodes_per_candidate) {
    return Status::failure(ErrorCode::ResourceLimit, "candidate node count is out of range");
  }
  if (candidate.links.size() + 1 != candidate.nodes.size() ||
      candidate.links.size() > limits.max_links_per_candidate) {
    return malformed("candidate links must exactly connect its consecutive nodes");
  }
  candidate.hop_count = static_cast<std::uint32_t>(candidate.links.size());

  // The traversal order is the candidate's identity and is preserved exactly:
  // a path from A to B is not the same object as a path from B to A. Only the
  // evidence vectors inside each node and link are canonicalized.
  for (NodeFact& node : candidate.nodes) {
    const Status status = canonicalize_node(node, limits);
    if (!status.ok()) {
      return status;
    }
  }
  for (LinkFact& link : candidate.links) {
    const Status status = canonicalize_link(link, limits);
    if (!status.ok()) {
      return status;
    }
  }
  const Status policy_status =
      canonicalize_refs(candidate.policies, [](const PolicyAttestation& ref) { return ref.policy; },
                        "policy");
  if (!policy_status.ok()) {
    return policy_status;
  }
  return validate_candidate(candidate, limits);
}

bool path_bandwidth_capability(const CandidatePath& candidate, CapabilityGeneration required,
                               std::int64_t& out_bits_per_second) {
  if (candidate.links.empty() || !required.is_valid()) {
    return false;
  }
  std::int64_t bottleneck = 0;
  bool first = true;
  for (const LinkFact& link : candidate.links) {
    if (link.bandwidth.model == CapabilityModel::None || link.bandwidth.generation != required) {
      return false;
    }
    if (link.bandwidth.bits_per_second < 0) {
      return false;
    }
    if (first || link.bandwidth.bits_per_second < bottleneck) {
      bottleneck = link.bandwidth.bits_per_second;
    }
    first = false;
  }
  out_bits_per_second = bottleneck;
  return true;
}

Digest256 candidate_digest(const CandidatePath& candidate) {
  SemanticHasher hasher;
  hasher.begin("crf.candidate.v1");
  hasher.put_u64(candidate.path.value());
  hasher.put_u64(candidate.authority_generation.value());
  hasher.put_u8(static_cast<std::uint8_t>(candidate.authority_verdict));
  hasher.put_u64(candidate.planner_generation.value());
  hasher.put_bool(candidate.has_planner_rank);
  hasher.put_u32(candidate.planner_rank);
  hasher.put_bool(candidate.has_planner_cost);
  hasher.put_i64(candidate.planner_cost);
  hasher.put_u8(static_cast<std::uint8_t>(candidate.cost_model));
  hasher.put_u32(candidate.hop_count);
  hasher.put_u32(static_cast<std::uint32_t>(candidate.nodes.size()));
  for (const NodeFact& node : candidate.nodes) {
    hasher.put_u64(node.node.value());
    hasher.put_u64(node.tier.value());
    hasher.put_u64(node.site.value());
    hasher.put_u32(static_cast<std::uint32_t>(node.localities.size()));
    for (const LocalityRef& ref : node.localities) feed_locality(hasher, ref);
    hasher.put_u32(static_cast<std::uint32_t>(node.domains.size()));
    for (const FailureDomainRef& ref : node.domains) feed_domain(hasher, ref);
    hasher.put_u32(static_cast<std::uint32_t>(node.capabilities.size()));
    for (const CapabilityRef& ref : node.capabilities) feed_capability(hasher, ref);
    hasher.put_u32(static_cast<std::uint32_t>(node.isolation.size()));
    for (const IsolationAttestation& ref : node.isolation) feed_isolation(hasher, ref);
  }
  hasher.put_u32(static_cast<std::uint32_t>(candidate.links.size()));
  for (const LinkFact& link : candidate.links) {
    hasher.put_u64(link.link.value());
    hasher.put_u64(link.endpoints[0].value());
    hasher.put_u64(link.endpoints[1].value());
    hasher.put_u8(static_cast<std::uint8_t>(link.bandwidth.model));
    hasher.put_u8(static_cast<std::uint8_t>(link.bandwidth.provenance));
    hasher.put_i64(link.bandwidth.bits_per_second);
    hasher.put_u64(link.bandwidth.generation.value());
    hasher.put_u32(static_cast<std::uint32_t>(link.domains.size()));
    for (const FailureDomainRef& ref : link.domains) feed_domain(hasher, ref);
    hasher.put_u32(static_cast<std::uint32_t>(link.capabilities.size()));
    for (const CapabilityRef& ref : link.capabilities) feed_capability(hasher, ref);
    hasher.put_u32(static_cast<std::uint32_t>(link.isolation.size()));
    for (const IsolationAttestation& ref : link.isolation) feed_isolation(hasher, ref);
  }
  hasher.put_u8(static_cast<std::uint8_t>(candidate.latency.source));
  hasher.put_u8(static_cast<std::uint8_t>(candidate.latency.provenance));
  hasher.put_i64(candidate.latency.micros);
  hasher.put_u64(candidate.latency.planner_generation.value());
  hasher.put_u64(candidate.latency.observed_generation.value());
  hasher.put_u32(static_cast<std::uint32_t>(candidate.policies.size()));
  for (const PolicyAttestation& ref : candidate.policies) {
    hasher.put_u64(ref.policy.value());
    hasher.put_u64(ref.generation.value());
  }
  feed_evidence(hasher, candidate.evidence);
  return hasher.finish();
}

bool candidate_canonical_less(const CandidatePath& a, const CandidatePath& b) noexcept {
  return a.path < b.path;
}

int compare_node_sequences(const CandidatePath& a, const CandidatePath& b) noexcept {
  const std::size_t shared = a.nodes.size() < b.nodes.size() ? a.nodes.size() : b.nodes.size();
  for (std::size_t index = 0; index < shared; ++index) {
    if (a.nodes[index].node < b.nodes[index].node) return -1;
    if (b.nodes[index].node < a.nodes[index].node) return 1;
  }
  if (a.nodes.size() != b.nodes.size()) return a.nodes.size() < b.nodes.size() ? -1 : 1;
  return 0;
}

void encode_candidate(ByteWriter& writer, const CandidatePath& candidate) {
  writer.put_u64(candidate.path.value());
  writer.put_u64(candidate.authority_generation.value());
  writer.put_u8(static_cast<std::uint8_t>(candidate.authority_verdict));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u64(candidate.planner_generation.value());
  writer.put_bool(candidate.has_planner_rank);
  writer.put_u32(candidate.planner_rank);
  writer.put_bool(candidate.has_planner_cost);
  writer.put_i64(candidate.planner_cost);
  writer.put_u8(static_cast<std::uint8_t>(candidate.cost_model));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(candidate.hop_count);
  writer.put_u32(static_cast<std::uint32_t>(candidate.nodes.size()));
  for (const NodeFact& node : candidate.nodes) {
    writer.put_u64(node.node.value());
    writer.put_u64(node.tier.value());
    writer.put_u64(node.site.value());
    writer.put_u32(static_cast<std::uint32_t>(node.localities.size()));
    for (const LocalityRef& ref : node.localities) write_locality(writer, ref);
    writer.put_u32(static_cast<std::uint32_t>(node.domains.size()));
    for (const FailureDomainRef& ref : node.domains) write_domain(writer, ref);
    writer.put_u32(static_cast<std::uint32_t>(node.capabilities.size()));
    for (const CapabilityRef& ref : node.capabilities) write_capability(writer, ref);
    writer.put_u32(static_cast<std::uint32_t>(node.isolation.size()));
    for (const IsolationAttestation& ref : node.isolation) write_isolation(writer, ref);
  }
  writer.put_u32(static_cast<std::uint32_t>(candidate.links.size()));
  for (const LinkFact& link : candidate.links) {
    writer.put_u64(link.link.value());
    writer.put_u64(link.endpoints[0].value());
    writer.put_u64(link.endpoints[1].value());
    writer.put_u8(static_cast<std::uint8_t>(link.bandwidth.model));
    writer.put_u8(static_cast<std::uint8_t>(link.bandwidth.provenance));
    writer.put_u16(0);
    writer.put_u32(0);
    writer.put_i64(link.bandwidth.bits_per_second);
    writer.put_u64(link.bandwidth.generation.value());
    writer.put_u64(link.bandwidth.observed_tick);
    writer.put_u32(static_cast<std::uint32_t>(link.domains.size()));
    for (const FailureDomainRef& ref : link.domains) write_domain(writer, ref);
    writer.put_u32(static_cast<std::uint32_t>(link.capabilities.size()));
    for (const CapabilityRef& ref : link.capabilities) write_capability(writer, ref);
    writer.put_u32(static_cast<std::uint32_t>(link.isolation.size()));
    for (const IsolationAttestation& ref : link.isolation) write_isolation(writer, ref);
  }
  writer.put_u8(static_cast<std::uint8_t>(candidate.latency.source));
  writer.put_u8(static_cast<std::uint8_t>(candidate.latency.provenance));
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_i64(candidate.latency.micros);
  writer.put_u64(candidate.latency.planner_generation.value());
  writer.put_u64(candidate.latency.observed_generation.value());
  writer.put_u64(candidate.latency.observed_tick);
  writer.put_u32(static_cast<std::uint32_t>(candidate.policies.size()));
  for (const PolicyAttestation& ref : candidate.policies) {
    writer.put_u64(ref.policy.value());
    writer.put_u64(ref.generation.value());
  }
  writer.put_u64(candidate.evidence.topology.value());
  writer.put_u64(candidate.evidence.link_state.value());
  writer.put_u64(candidate.evidence.capability.value());
  writer.put_u64(candidate.evidence.failure_domain.value());
  writer.put_u64(candidate.evidence.policy.value());
  writer.put_u64(candidate.evidence.planner.value());
  writer.put_u64(candidate.evidence.path_authority.value());
  writer.put_u32(candidate.evidence.consulted);
  writer.put_u64(candidate.evidence.captured_tick);
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

bool decode_candidate(ByteReader& reader, const Limits& limits, CandidatePath& out) {
  std::uint64_t path = 0;
  std::uint64_t authority_generation = 0;
  std::uint8_t verdict = 0;
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.u64(path) || !reader.u64(authority_generation) || !reader.u8(verdict) ||
      !reader.u8(padding8) || !reader.u16(padding16) || !reader.u32(padding32)) {
    return false;
  }
  if (path == 0 || !PathAuthorityGeneration::is_representable(authority_generation) ||
      verdict > 2 || padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  out.path = PathId::from_value(path);
  out.authority_generation = PathAuthorityGeneration::from_value(authority_generation);
  out.authority_verdict = static_cast<PathAuthorityVerdict>(verdict);
  if (!read_generation_field(reader, out.planner_generation) ||
      !reader.boolean(out.has_planner_rank) || !reader.u32(out.planner_rank) ||
      !reader.boolean(out.has_planner_cost) || !reader.i64(out.planner_cost)) {
    return false;
  }
  std::uint8_t cost_model = 0;
  std::uint8_t cost_padding8 = 0;
  std::uint16_t cost_padding16 = 0;
  if (!reader.u8(cost_model) || !reader.u8(cost_padding8) || !reader.u16(cost_padding16) ||
      !reader.u32(out.hop_count)) {
    return false;
  }
  if (cost_model > 3 || cost_padding8 != 0 || cost_padding16 != 0) {
    reader.fail();
    return false;
  }
  out.cost_model = static_cast<PlannerCostModel>(cost_model);

  std::uint32_t node_count = 0;
  if (!reader.bounded_length(limits.max_nodes_per_candidate, node_count)) {
    return false;
  }
  out.nodes.clear();
  out.nodes.reserve(node_count);
  for (std::uint32_t index = 0; index < node_count; ++index) {
    NodeFact node;
    std::uint64_t node_id = 0;
    std::uint64_t tier = 0;
    std::uint64_t site = 0;
    if (!reader.u64(node_id) || !reader.u64(tier) || !reader.u64(site)) {
      return false;
    }
    if (node_id == 0) {
      reader.fail();
      return false;
    }
    node.node = NodeId::from_value(node_id);
    node.tier = TierId::from_value(tier);
    node.site = SiteId::from_value(site);
    std::uint32_t count = 0;
    if (!reader.bounded_length(limits.max_localities_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      LocalityRef ref;
      if (!read_locality(reader, ref)) {
        return false;
      }
      node.localities.push_back(ref);
    }
    if (!reader.bounded_length(limits.max_domains_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      FailureDomainRef ref;
      if (!read_domain(reader, ref)) {
        return false;
      }
      node.domains.push_back(ref);
    }
    if (!reader.bounded_length(limits.max_capabilities_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      CapabilityRef ref;
      if (!read_capability(reader, ref)) {
        return false;
      }
      node.capabilities.push_back(ref);
    }
    if (!reader.bounded_length(limits.max_capabilities_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      IsolationAttestation ref;
      if (!read_isolation(reader, ref)) {
        return false;
      }
      node.isolation.push_back(ref);
    }
    out.nodes.push_back(std::move(node));
  }

  std::uint32_t link_count = 0;
  if (!reader.bounded_length(limits.max_links_per_candidate, link_count)) {
    return false;
  }
  out.links.clear();
  out.links.reserve(link_count);
  for (std::uint32_t index = 0; index < link_count; ++index) {
    LinkFact link;
    std::uint64_t link_id = 0;
    std::uint64_t endpoint_a = 0;
    std::uint64_t endpoint_b = 0;
    std::uint8_t model = 0;
    std::uint8_t provenance = 0;
    if (!reader.u64(link_id) || !reader.u64(endpoint_a) || !reader.u64(endpoint_b) ||
        !reader.u8(model) || !reader.u8(provenance) || !reader.u16(padding16) || !reader.u32(padding32)) {
      return false;
    }
    if (link_id == 0 || endpoint_a == 0 || endpoint_b == 0 || model > 2 || provenance > 8 ||
        padding16 != 0 || padding32 != 0) {
      reader.fail();
      return false;
    }
    link.link = LinkId::from_value(link_id);
    link.endpoints[0] = NodeId::from_value(endpoint_a);
    link.endpoints[1] = NodeId::from_value(endpoint_b);
    link.bandwidth.model = static_cast<CapabilityModel>(model);
    link.bandwidth.provenance = static_cast<EvidenceProvenance>(provenance);
    if (!reader.i64(link.bandwidth.bits_per_second) ||
        !read_generation_field(reader, link.bandwidth.generation) ||
        !reader.u64(link.bandwidth.observed_tick)) {
      return false;
    }
    std::uint32_t count = 0;
    if (!reader.bounded_length(limits.max_domains_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      FailureDomainRef ref;
      if (!read_domain(reader, ref)) {
        return false;
      }
      link.domains.push_back(ref);
    }
    if (!reader.bounded_length(limits.max_capabilities_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      CapabilityRef ref;
      if (!read_capability(reader, ref)) {
        return false;
      }
      link.capabilities.push_back(ref);
    }
    if (!reader.bounded_length(limits.max_capabilities_per_entity, count)) {
      return false;
    }
    for (std::uint32_t item = 0; item < count; ++item) {
      IsolationAttestation ref;
      if (!read_isolation(reader, ref)) {
        return false;
      }
      link.isolation.push_back(ref);
    }
    out.links.push_back(std::move(link));
  }

  std::uint8_t latency_source = 0;
  std::uint8_t latency_provenance = 0;
  if (!reader.u8(latency_source) || !reader.u8(latency_provenance) || !reader.u16(padding16) ||
      !reader.u32(padding32)) {
    return false;
  }
  if (latency_source > 2 || latency_provenance > 8 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  out.latency.source = static_cast<LatencySource>(latency_source);
  out.latency.provenance = static_cast<EvidenceProvenance>(latency_provenance);
  if (!reader.i64(out.latency.micros) ||
      !read_generation_field(reader, out.latency.planner_generation) ||
      !read_generation_field(reader, out.latency.observed_generation) ||
      !reader.u64(out.latency.observed_tick)) {
    return false;
  }

  std::uint32_t policy_count = 0;
  if (!reader.bounded_length(limits.max_policies_per_candidate, policy_count)) {
    return false;
  }
  out.policies.clear();
  out.policies.reserve(policy_count);
  for (std::uint32_t index = 0; index < policy_count; ++index) {
    std::uint64_t policy = 0;
    std::uint64_t generation = 0;
    if (!reader.u64(policy) || !reader.u64(generation)) {
      return false;
    }
    if (policy == 0 || !PolicyGeneration::is_representable(generation)) {
      reader.fail();
      return false;
    }
    out.policies.push_back(PolicyAttestation{PolicyId::from_value(policy),
                                             PolicyGeneration::from_value(generation)});
  }

  if (!read_generation_field(reader, out.evidence.topology) ||
      !read_generation_field(reader, out.evidence.link_state) ||
      !read_generation_field(reader, out.evidence.capability) ||
      !read_generation_field(reader, out.evidence.failure_domain) ||
      !read_generation_field(reader, out.evidence.policy) ||
      !read_generation_field(reader, out.evidence.planner) ||
      !read_generation_field(reader, out.evidence.path_authority) ||
      !reader.u32(out.evidence.consulted) || !reader.u64(out.evidence.captured_tick)) {
    return false;
  }
  if (!reader.ok()) {
    return false;
  }
  const Status status = validate_candidate(out, limits);
  if (!status.ok()) {
    reader.fail();
    return false;
  }
  return true;
}

}  // namespace crf
