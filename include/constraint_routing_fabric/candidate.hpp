// Constraint Routing Fabric -- candidates and authoritative evidence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A candidate is produced by the Path Planner and carries an exact Path
// Authority verdict. Constraint Routing Fabric never searches the graph, never
// decides legality and never overrides Path Authority.
#ifndef CONSTRAINT_ROUTING_FABRIC_CANDIDATE_HPP
#define CONSTRAINT_ROUTING_FABRIC_CANDIDATE_HPP

#include <cstdint>
#include <vector>

#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Verdict of the Path Authority for the exact PathId at the exact
/// PathAuthorityGeneration the candidate carries.
enum class PathAuthorityVerdict : std::uint8_t {
  NotEvaluated = 0,
  Legal = 1,
  Rejected = 2,
};

/// Authoritative locality membership of an entity. Membership is an explicit
/// identity handed over by the topology authority.
struct LocalityRef {
  DomainKind kind{DomainKind::Unset};
  LocalityDomainId domain{};

  friend bool operator==(const LocalityRef& a, const LocalityRef& b) noexcept {
    return a.kind == b.kind && a.domain == b.domain;
  }
  friend bool operator<(const LocalityRef& a, const LocalityRef& b) noexcept {
    return a.kind != b.kind ? a.kind < b.kind : a.domain < b.domain;
  }
};

/// Authoritative failure-domain membership of an entity.
struct FailureDomainRef {
  DomainKind kind{DomainKind::Unset};
  FailureDomainId domain{};

  friend bool operator==(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    return a.kind == b.kind && a.domain == b.domain;
  }
  friend bool operator<(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    return a.kind != b.kind ? a.kind < b.kind : a.domain < b.domain;
  }
};

/// Capability evidence about an entity, bound to an exact capability generation.
/// A missing reference means UNKNOWN, never SUPPORTED.
struct CapabilityRef {
  CapabilityId capability{};
  CapabilityGeneration generation{};

  friend bool operator==(const CapabilityRef& a, const CapabilityRef& b) noexcept {
    return a.capability == b.capability && a.generation == b.generation;
  }
  friend bool operator<(const CapabilityRef& a, const CapabilityRef& b) noexcept {
    return a.capability != b.capability ? a.capability < b.capability : a.generation < b.generation;
  }
};

/// Policy attestation issued by the policy registry.
struct PolicyAttestation {
  PolicyId policy{};
  PolicyGeneration generation{};

  friend bool operator==(const PolicyAttestation& a, const PolicyAttestation& b) noexcept {
    return a.policy == b.policy && a.generation == b.generation;
  }
  friend bool operator<(const PolicyAttestation& a, const PolicyAttestation& b) noexcept {
    return a.policy != b.policy ? a.policy < b.policy : a.generation < b.generation;
  }
};

/// Proof that an entity belongs to an isolation class, bound to the exact
/// failure-domain generation that established it.
struct IsolationAttestation {
  IsolationClassId isolation_class{};
  FailureDomainGeneration generation{};

  friend bool operator==(const IsolationAttestation& a, const IsolationAttestation& b) noexcept {
    return a.isolation_class == b.isolation_class && a.generation == b.generation;
  }
  friend bool operator<(const IsolationAttestation& a, const IsolationAttestation& b) noexcept {
    return a.isolation_class != b.isolation_class ? a.isolation_class < b.isolation_class
                                                  : a.generation < b.generation;
  }
};

/// Latency figure with an explicit, non-interchangeable evidence model.
struct LatencyEvidence {
  LatencySource source{LatencySource::Unset};
  EvidenceProvenance provenance{EvidenceProvenance::None};
  std::int64_t micros{0};
  PlannerGeneration planner_generation{};
  LinkStateGeneration observed_generation{};
  std::uint64_t observed_tick{0};

  friend bool operator==(const LatencyEvidence& a, const LatencyEvidence& b) noexcept;
};

/// Bandwidth *capability* evidence. This is a declared capability threshold
/// model. It is not a reservation and it is not a delivered-throughput
/// measurement; no reservation is created by evaluating it.
struct BandwidthCapabilityEvidence {
  CapabilityModel model{CapabilityModel::None};
  EvidenceProvenance provenance{EvidenceProvenance::None};
  std::int64_t bits_per_second{0};
  CapabilityGeneration generation{};
  std::uint64_t observed_tick{0};

  friend bool operator==(const BandwidthCapabilityEvidence& a,
                         const BandwidthCapabilityEvidence& b) noexcept;
};

/// Authoritative facts about one node of a candidate path.
struct NodeFact {
  NodeId node{};
  TierId tier{};
  SiteId site{};
  std::vector<LocalityRef> localities{};
  std::vector<FailureDomainRef> domains{};
  std::vector<CapabilityRef> capabilities{};
  std::vector<IsolationAttestation> isolation{};
};

/// Authoritative facts about one link of a candidate path.
struct LinkFact {
  LinkId link{};
  NodeId endpoints[2]{};
  BandwidthCapabilityEvidence bandwidth{};
  std::vector<FailureDomainRef> domains{};
  std::vector<CapabilityRef> capabilities{};
  std::vector<IsolationAttestation> isolation{};
};

/// Exact evidence generations a candidate was assembled from.
struct EvidenceGenerationSet {
  TopologyGeneration topology{};
  LinkStateGeneration link_state{};
  CapabilityGeneration capability{};
  FailureDomainGeneration failure_domain{};
  PolicyGeneration policy{};
  PlannerGeneration planner{};
  PathAuthorityGeneration path_authority{};
  EvidenceFamilyMask consulted{0};
  std::uint64_t captured_tick{0};

  friend bool operator==(const EvidenceGenerationSet& a, const EvidenceGenerationSet& b) noexcept;
};

/// What the constraint set requires of the authoritative evidence.
struct EvidenceRequirements {
  TopologyGeneration topology{};
  LinkStateGeneration link_state{};
  CapabilityGeneration capability{};
  FailureDomainGeneration failure_domain{};
  PolicyGeneration policy{};
  PlannerGeneration planner{};
  PathAuthorityGeneration path_authority{};
  /// Zero disables the age bound. Otherwise evidence older than this many ticks
  /// relative to the evaluation tick is stale.
  std::uint64_t max_evidence_age_ticks{0};
};

/// One candidate produced by the Path Planner and adjudicated by Path Authority.
struct CandidatePath {
  PathId path{};
  PathAuthorityGeneration authority_generation{};
  PathAuthorityVerdict authority_verdict{PathAuthorityVerdict::NotEvaluated};

  PlannerGeneration planner_generation{};
  bool has_planner_rank{false};
  std::uint32_t planner_rank{0};
  bool has_planner_cost{false};
  std::int64_t planner_cost{0};
  PlannerCostModel cost_model{PlannerCostModel::None};

  std::uint32_t hop_count{0};
  std::vector<NodeFact> nodes{};
  std::vector<LinkFact> links{};
  LatencyEvidence latency{};
  std::vector<PolicyAttestation> policies{};

  EvidenceGenerationSet evidence{};
};

/// Canonicalizes a candidate in place: sorts every evidence vector, rejects
/// duplicates that disagree, and validates the node/link sequence.
[[nodiscard]] Status canonicalize_candidate(CandidatePath& candidate, const Limits& limits);

/// Structural validation without mutation.
[[nodiscard]] Status validate_candidate(const CandidatePath& candidate, const Limits& limits);

/// Bottleneck bandwidth capability of the path. Returns false when any link
/// lacks capability evidence at the required generation. This figure is a
/// capability floor, never a reservation and never delivered throughput.
[[nodiscard]] bool path_bandwidth_capability(const CandidatePath& candidate,
                                             CapabilityGeneration required,
                                             std::int64_t& out_bits_per_second);

/// Deterministic digest of a candidate's semantic content.
[[nodiscard]] Digest256 candidate_digest(const CandidatePath& candidate);

/// Total order used to canonicalize a candidate population. Identity only; the
/// order in which candidates arrive is never observable.
[[nodiscard]] bool candidate_canonical_less(const CandidatePath& a, const CandidatePath& b) noexcept;

/// Lexicographic comparison of the node sequences, used by the documented
/// node-sequence tie-break. Returns <0, 0 or >0.
[[nodiscard]] int compare_node_sequences(const CandidatePath& a, const CandidatePath& b) noexcept;

void encode_candidate(ByteWriter& writer, const CandidatePath& candidate);
[[nodiscard]] bool decode_candidate(ByteReader& reader, const Limits& limits, CandidatePath& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_CANDIDATE_HPP
