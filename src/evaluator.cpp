// Constraint Routing Fabric -- pure deterministic evaluator.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/evaluator.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <string>
#include <vector>

#include "constraint_routing_fabric/ordering.hpp"

namespace crf {
namespace {

/// Maximum reasons emitted for a single failing mandatory constraint, before
/// the two evaluation-wide bounds in ::crf::canonicalize_reasons are applied.
/// The explanation contract is a bounded, complete-at-constraint-granularity
/// list: at least one reason per failed constraint survives.
constexpr std::size_t kMaxReasonsPerConstraint = 8;

struct State {
  const ConstraintSet& set;
  const CandidatePath& candidate;
  const EvaluationContext& context;
  std::vector<Reason> reasons;
  std::vector<PreferenceSlot> preferences;
  EvidenceFamilyMask consulted{0};
  bool truncated{false};
};

void push_reason(State& state, Reason reason) {
  std::size_t emitted = 0;
  for (const Reason& existing : state.reasons) {
    if (existing.constraint_ordinal == reason.constraint_ordinal) {
      ++emitted;
    }
  }
  if (emitted >= kMaxReasonsPerConstraint) {
    state.truncated = true;
    return;
  }
  reason.reason_class = reason_class_of(reason.code);
  state.reasons.push_back(reason);
}

[[nodiscard]] Reason make_reason(const Constraint& constraint, std::uint32_t ordinal, ReasonCode code,
                                 EvidenceFamily family, SubjectKind subject_kind = SubjectKind::None,
                                 std::uint64_t subject = 0, std::uint64_t expected = 0,
                                 std::uint64_t actual = 0) {
  Reason reason;
  reason.code = code;
  reason.reason_class = reason_class_of(code);
  reason.constraint = constraint.id;
  reason.constraint_kind = constraint.kind;
  reason.constraint_ordinal = ordinal;
  reason.family = family;
  reason.subject_kind = subject_kind;
  reason.subject = subject;
  reason.expected = expected;
  reason.actual = actual;
  return reason;
}

[[nodiscard]] EvidenceFamilyMask families_of(const Constraint& constraint) noexcept {
  if (constraint.kind == ConstraintKind::MaxLatency) {
    return constraint.latency_source == LatencySource::PlannerCost
               ? family_bit(EvidenceFamily::Planner)
               : family_bit(EvidenceFamily::LinkState);
  }
  return evidence_families(constraint.kind);
}

// --- evidence lookups -------------------------------------------------------

[[nodiscard]] const LocalityRef* find_locality(const std::vector<LocalityRef>& values,
                                               DomainKind kind) noexcept {
  const auto found = std::lower_bound(values.begin(), values.end(), kind,
                                      [](const LocalityRef& ref, DomainKind wanted) {
                                        return ref.kind < wanted;
                                      });
  if (found == values.end() || found->kind != kind) {
    return nullptr;
  }
  return &*found;
}

[[nodiscard]] const FailureDomainRef* find_domain(const std::vector<FailureDomainRef>& values,
                                                  DomainKind kind) noexcept {
  const auto found = std::lower_bound(values.begin(), values.end(), kind,
                                      [](const FailureDomainRef& ref, DomainKind wanted) {
                                        return ref.kind < wanted;
                                      });
  if (found == values.end() || found->kind != kind) {
    return nullptr;
  }
  return &*found;
}

[[nodiscard]] const CapabilityRef* find_capability(const std::vector<CapabilityRef>& values,
                                                   CapabilityId capability) noexcept {
  const auto found = std::lower_bound(values.begin(), values.end(), capability,
                                      [](const CapabilityRef& ref, CapabilityId wanted) {
                                        return ref.capability < wanted;
                                      });
  if (found == values.end() || !(found->capability == capability)) {
    return nullptr;
  }
  return &*found;
}

[[nodiscard]] const IsolationAttestation* find_isolation(
    const std::vector<IsolationAttestation>& values, IsolationClassId isolation_class) noexcept {
  const auto found = std::lower_bound(values.begin(), values.end(), isolation_class,
                                      [](const IsolationAttestation& ref, IsolationClassId wanted) {
                                        return ref.isolation_class < wanted;
                                      });
  if (found == values.end() || !(found->isolation_class == isolation_class)) {
    return nullptr;
  }
  return &*found;
}

[[nodiscard]] const PolicyAttestation* find_policy(const std::vector<PolicyAttestation>& values,
                                                   PolicyId policy) noexcept {
  const auto found = std::lower_bound(values.begin(), values.end(), policy,
                                      [](const PolicyAttestation& ref, PolicyId wanted) {
                                        return ref.policy < wanted;
                                      });
  if (found == values.end() || !(found->policy == policy)) {
    return nullptr;
  }
  return &*found;
}

struct EntityView {
  std::uint64_t identity;
  SubjectKind kind;
  const std::vector<FailureDomainRef>* domains;
  const std::vector<CapabilityRef>* capabilities;
  const std::vector<IsolationAttestation>* isolation;
};

[[nodiscard]] std::vector<EntityView> entities_of(const CandidatePath& candidate) {
  std::vector<EntityView> entities;
  entities.reserve(candidate.nodes.size() + candidate.links.size());
  for (const NodeFact& node : candidate.nodes) {
    entities.push_back(EntityView{node.node.value(), SubjectKind::Node, &node.domains,
                                  &node.capabilities, &node.isolation});
  }
  for (const LinkFact& link : candidate.links) {
    entities.push_back(EntityView{link.link.value(), SubjectKind::Link, &link.domains,
                                  &link.capabilities, &link.isolation});
  }
  return entities;
}

// --- per-constraint mandatory evaluation ------------------------------------

void check_max_latency(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const EvidenceFamily wanted_family = constraint.latency_source == LatencySource::PlannerCost
                                           ? EvidenceFamily::Planner
                                           : EvidenceFamily::LinkState;
  const LatencyEvidence& latency = state.candidate.latency;
  if (latency.source == LatencySource::Unset) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::LatencyEvidenceUnavailable,
                                   wanted_family, SubjectKind::CandidatePath,
                                   state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.latency_source)));
    return;
  }
  if (latency.source != constraint.latency_source) {
    // Modelled planner cost and observed latency are never mixed silently.
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::LatencyEvidenceUnavailable,
                                   wanted_family, SubjectKind::CandidatePath,
                                   state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.latency_source),
                                   static_cast<std::uint64_t>(latency.source)));
    return;
  }
  if (latency.micros > constraint.bound) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::MaxLatencyExceeded, wanted_family,
                                   SubjectKind::CandidatePath, state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.bound),
                                   static_cast<std::uint64_t>(latency.micros)));
  }
}

void check_min_bandwidth(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  std::int64_t bottleneck = 0;
  if (!path_bandwidth_capability(state.candidate, state.context.current.capability, bottleneck)) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::BandwidthCapabilityUnavailable,
                                   EvidenceFamily::Capability, SubjectKind::CandidatePath,
                                   state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.bound)));
    return;
  }
  if (bottleneck < constraint.bound) {
    // This is a capability-evidence comparison. It reserves nothing and says
    // nothing about delivered throughput.
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::MinBandwidthCapabilityNotMet,
                                   EvidenceFamily::Capability, SubjectKind::CandidatePath,
                                   state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.bound),
                                   static_cast<std::uint64_t>(bottleneck)));
  }
}

void check_max_hop_count(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const auto hops = static_cast<std::int64_t>(state.candidate.hop_count);
  if (hops > constraint.bound) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::MaxHopCountExceeded,
                                   EvidenceFamily::Planner, SubjectKind::CandidatePath,
                                   state.candidate.path.value(),
                                   static_cast<std::uint64_t>(constraint.bound),
                                   static_cast<std::uint64_t>(hops)));
  }
}

void check_required_node(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeId& wanted : constraint.nodes) {
    bool present = false;
    for (const NodeFact& node : state.candidate.nodes) {
      if (node.node == wanted) {
        present = true;
        break;
      }
    }
    if (!present) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::RequiredNodeAbsent,
                                     EvidenceFamily::Topology, SubjectKind::Node, wanted.value()));
    }
  }
}

void check_forbidden_node(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeId& forbidden : constraint.nodes) {
    for (const NodeFact& node : state.candidate.nodes) {
      if (node.node == forbidden) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenNodePresent,
                                       EvidenceFamily::Topology, SubjectKind::Node,
                                       forbidden.value()));
      }
    }
  }
}

void check_required_link(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const LinkId& wanted : constraint.links) {
    bool present = false;
    for (const LinkFact& link : state.candidate.links) {
      if (link.link == wanted) {
        present = true;
        break;
      }
    }
    if (!present) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::RequiredLinkAbsent,
                                     EvidenceFamily::Topology, SubjectKind::Link, wanted.value()));
    }
  }
}

void check_forbidden_link(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const LinkId& forbidden : constraint.links) {
    for (const LinkFact& link : state.candidate.links) {
      if (link.link == forbidden) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenLinkPresent,
                                       EvidenceFamily::Topology, SubjectKind::Link,
                                       forbidden.value()));
      }
    }
  }
}

void check_required_tier(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeFact& node : state.candidate.nodes) {
    if (!node.tier.is_valid()) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::TierEvidenceUnavailable,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value()));
      continue;
    }
    if (!std::binary_search(constraint.tiers.begin(), constraint.tiers.end(), node.tier)) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::RequiredTierNotMet,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     0, node.tier.value()));
    }
  }
}

void check_forbidden_tier(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeFact& node : state.candidate.nodes) {
    if (!node.tier.is_valid()) {
      if (constraint.unknown_policy == UnknownPolicy::FailClosed) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::TierEvidenceUnavailable,
                                       EvidenceFamily::Topology, SubjectKind::Node,
                                       node.node.value()));
      }
      continue;
    }
    if (std::binary_search(constraint.tiers.begin(), constraint.tiers.end(), node.tier)) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenTierPresent,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     0, node.tier.value()));
    }
  }
}

void check_required_site(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeFact& node : state.candidate.nodes) {
    if (!node.site.is_valid()) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::SiteEvidenceUnavailable,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value()));
      continue;
    }
    if (!std::binary_search(constraint.sites.begin(), constraint.sites.end(), node.site)) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::RequiredSiteNotMet,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     0, node.site.value()));
    }
  }
}

void check_forbidden_site(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeFact& node : state.candidate.nodes) {
    if (!node.site.is_valid()) {
      if (constraint.unknown_policy == UnknownPolicy::FailClosed) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::SiteEvidenceUnavailable,
                                       EvidenceFamily::Topology, SubjectKind::Node,
                                       node.node.value()));
      }
      continue;
    }
    if (std::binary_search(constraint.sites.begin(), constraint.sites.end(), node.site)) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenSitePresent,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     0, node.site.value()));
    }
  }
}

void check_locality_scope(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const NodeFact& node : state.candidate.nodes) {
    const LocalityRef* membership = find_locality(node.localities, constraint.domain_kind);
    if (membership == nullptr) {
      // Locality is never inferred from a name prefix. Absent authoritative
      // membership is UNKNOWN, not a silent pass.
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::LocalityEvidenceUnavailable,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     constraint.locality_domain.value()));
      continue;
    }
    if (!(membership->domain == constraint.locality_domain)) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::LocalityScopeViolated,
                                     EvidenceFamily::Topology, SubjectKind::Node, node.node.value(),
                                     constraint.locality_domain.value(), membership->domain.value()));
    }
  }
}

void check_isolation_class(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const std::vector<EntityView> entities = entities_of(state.candidate);
  for (const EntityView& entity : entities) {
    const IsolationAttestation* proof =
        find_isolation(*entity.isolation, constraint.isolation_class);
    if (proof == nullptr) {
      if (entity.isolation->empty()) {
        // No common label was searched for and none is claimed: the absence of
        // positive isolation evidence is UNKNOWN, never an independence claim.
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::IsolationEvidenceUnavailable,
                                       EvidenceFamily::FailureDomain, entity.kind, entity.identity,
                                       constraint.isolation_class.value()));
      } else {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::IsolationClassNotProven,
                                       EvidenceFamily::FailureDomain, entity.kind, entity.identity,
                                       constraint.isolation_class.value(),
                                       entity.isolation->front().isolation_class.value()));
      }
      continue;
    }
    if (proof->generation != state.context.current.failure_domain) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::IsolationEvidenceUnavailable,
                                     EvidenceFamily::FailureDomain, entity.kind, entity.identity,
                                     state.context.current.failure_domain.value(),
                                     proof->generation.value()));
    }
  }
}

void check_required_capability(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const std::vector<EntityView> entities = entities_of(state.candidate);
  for (const CapabilityId& wanted : constraint.capabilities) {
    for (const EntityView& entity : entities) {
      const CapabilityRef* ref = find_capability(*entity.capabilities, wanted);
      if (ref == nullptr) {
        // Missing capability evidence is UNKNOWN, never SUPPORTED.
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::CapabilityEvidenceUnavailable,
                                       EvidenceFamily::Capability, entity.kind, entity.identity,
                                       wanted.value()));
        continue;
      }
      if (ref->generation != state.context.current.capability) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::CapabilityEvidenceUnavailable,
                                       EvidenceFamily::Capability, entity.kind, entity.identity,
                                       state.context.current.capability.value(),
                                       ref->generation.value()));
      }
    }
  }
}

void check_forbidden_capability(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const std::vector<EntityView> entities = entities_of(state.candidate);
  for (const CapabilityId& forbidden : constraint.capabilities) {
    for (const EntityView& entity : entities) {
      const CapabilityRef* ref = find_capability(*entity.capabilities, forbidden);
      if (ref == nullptr) {
        if (constraint.unknown_policy == UnknownPolicy::FailClosed) {
          push_reason(state,
                      make_reason(constraint, ordinal, ReasonCode::CapabilityEvidenceUnavailable,
                                  EvidenceFamily::Capability, entity.kind, entity.identity,
                                  forbidden.value()));
        }
        continue;
      }
      if (ref->generation != state.context.current.capability) {
        push_reason(state, make_reason(constraint, ordinal, ReasonCode::CapabilityEvidenceUnavailable,
                                       EvidenceFamily::Capability, entity.kind, entity.identity,
                                       state.context.current.capability.value(),
                                       ref->generation.value()));
        continue;
      }
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenCapabilityPresent,
                                     EvidenceFamily::Capability, entity.kind, entity.identity,
                                     forbidden.value()));
    }
  }
}

struct DomainScan {
  bool complete{true};
  bool recorded_incomplete{false};
  std::set<std::uint64_t> domains{};
  std::uint64_t first_incomplete_entity{0};
  SubjectKind first_incomplete_kind{SubjectKind::Node};
};

[[nodiscard]] DomainScan scan_domains(const CandidatePath& candidate, DomainKind kind) {
  DomainScan scan;
  const std::vector<EntityView> entities = entities_of(candidate);
  for (const EntityView& entity : entities) {
    const FailureDomainRef* ref = find_domain(*entity.domains, kind);
    if (ref == nullptr) {
      scan.complete = false;
      if (!scan.recorded_incomplete) {
        scan.recorded_incomplete = true;
        scan.first_incomplete_entity = entity.identity;
        scan.first_incomplete_kind = entity.kind;
      }
      continue;
    }
    scan.domains.insert(ref->domain.value());
  }
  return scan;
}

void check_required_domain_relation(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  const DomainScan scan = scan_domains(state.candidate, constraint.domain_kind);
  if (!scan.complete) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::FailureDomainEvidenceUnavailable,
                                   EvidenceFamily::FailureDomain, scan.first_incomplete_kind,
                                   scan.first_incomplete_entity));
    return;
  }
  const auto distinct = static_cast<std::int64_t>(scan.domains.size());
  if (distinct < constraint.bound) {
    push_reason(state, make_reason(constraint, ordinal,
                                   ReasonCode::RequiredFailureDomainRelationNotMet,
                                   EvidenceFamily::FailureDomain, SubjectKind::FailureDomain,
                                   static_cast<std::uint64_t>(constraint.domain_kind),
                                   static_cast<std::uint64_t>(constraint.bound),
                                   static_cast<std::uint64_t>(distinct)));
  }
}

void check_forbidden_domain_relation(const Constraint& constraint, std::uint32_t ordinal,
                                     State& state) {
  const DomainScan scan = scan_domains(state.candidate, constraint.domain_kind);
  const bool fail_closed = constraint.unknown_policy == UnknownPolicy::FailClosed;
  if (!scan.complete && fail_closed) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::FailureDomainEvidenceUnavailable,
                                   EvidenceFamily::FailureDomain, scan.first_incomplete_kind,
                                   scan.first_incomplete_entity));
    return;
  }
  if (constraint.domain_relation == DomainRelation::Shared) {
    if (scan.complete && scan.domains.size() == 1) {
      push_reason(state, make_reason(constraint, ordinal,
                                     ReasonCode::ForbiddenFailureDomainRelationMet,
                                     EvidenceFamily::FailureDomain, SubjectKind::FailureDomain,
                                     static_cast<std::uint64_t>(constraint.domain_kind), 0,
                                     *scan.domains.begin()));
    }
    return;
  }
  const auto distinct = static_cast<std::int64_t>(scan.domains.size());
  if (distinct >= constraint.bound) {
    push_reason(state, make_reason(constraint, ordinal, ReasonCode::ForbiddenFailureDomainRelationMet,
                                   EvidenceFamily::FailureDomain, SubjectKind::FailureDomain,
                                   static_cast<std::uint64_t>(constraint.domain_kind),
                                   static_cast<std::uint64_t>(constraint.bound),
                                   static_cast<std::uint64_t>(distinct)));
  }
}

void check_administrative_policy(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  for (const PolicyId& wanted : constraint.policies) {
    const PolicyAttestation* attestation = find_policy(state.candidate.policies, wanted);
    if (attestation == nullptr) {
      push_reason(state, make_reason(constraint, ordinal,
                                     ReasonCode::AdministrativePolicyNotSatisfied,
                                     EvidenceFamily::Policy, SubjectKind::Policy, wanted.value()));
      continue;
    }
    if (attestation->generation != state.context.current.policy) {
      push_reason(state, make_reason(constraint, ordinal, ReasonCode::PolicyEvidenceUnavailable,
                                     EvidenceFamily::Policy, SubjectKind::Policy, wanted.value(),
                                     state.context.current.policy.value(),
                                     attestation->generation.value()));
    }
  }
}

void evaluate_mandatory(const Constraint& constraint, std::uint32_t ordinal, State& state) {
  switch (constraint.kind) {
    case ConstraintKind::MaxLatency: check_max_latency(constraint, ordinal, state); return;
    case ConstraintKind::MinBandwidthCapability: check_min_bandwidth(constraint, ordinal, state); return;
    case ConstraintKind::MaxHopCount: check_max_hop_count(constraint, ordinal, state); return;
    case ConstraintKind::RequiredNode: check_required_node(constraint, ordinal, state); return;
    case ConstraintKind::ForbiddenNode: check_forbidden_node(constraint, ordinal, state); return;
    case ConstraintKind::RequiredLink: check_required_link(constraint, ordinal, state); return;
    case ConstraintKind::ForbiddenLink: check_forbidden_link(constraint, ordinal, state); return;
    case ConstraintKind::RequiredTier: check_required_tier(constraint, ordinal, state); return;
    case ConstraintKind::ForbiddenTier: check_forbidden_tier(constraint, ordinal, state); return;
    case ConstraintKind::RequiredSite: check_required_site(constraint, ordinal, state); return;
    case ConstraintKind::ForbiddenSite: check_forbidden_site(constraint, ordinal, state); return;
    case ConstraintKind::LocalityScope: check_locality_scope(constraint, ordinal, state); return;
    case ConstraintKind::IsolationClass: check_isolation_class(constraint, ordinal, state); return;
    case ConstraintKind::RequiredCapability:
      check_required_capability(constraint, ordinal, state);
      return;
    case ConstraintKind::ForbiddenCapability:
      check_forbidden_capability(constraint, ordinal, state);
      return;
    case ConstraintKind::RequiredFailureDomainRelation:
      check_required_domain_relation(constraint, ordinal, state);
      return;
    case ConstraintKind::ForbiddenFailureDomainRelation:
      check_forbidden_domain_relation(constraint, ordinal, state);
      return;
    case ConstraintKind::AdministrativePolicy:
      check_administrative_policy(constraint, ordinal, state);
      return;
    case ConstraintKind::Unset:
    default:
      return;
  }
}

/// Preference evaluation reuses the mandatory predicate implementation exactly,
/// so a preference can never disagree with the hard result it ranks. A
/// preference never contributes a reason and never rescues a hard failure.
[[nodiscard]] PreferenceSlot evaluate_preference(const Constraint& constraint, std::uint32_t ordinal,
                                                 const State& outer) {
  PreferenceSlot slot;
  slot.constraint = constraint.id;
  slot.kind = constraint.kind;
  slot.constraint_ordinal = ordinal;
  slot.rank = constraint.preference_rank;
  slot.weight = constraint.preference_weight;

  State scratch{outer.set, outer.candidate, outer.context, {}, {}, 0, false};
  evaluate_mandatory(constraint, ordinal, scratch);
  slot.satisfied = scratch.reasons.empty();
  slot.margin = slot.satisfied ? 1 : 0;

  switch (constraint.kind) {
    case ConstraintKind::MaxLatency: {
      const LatencyEvidence& latency = outer.candidate.latency;
      if (latency.source != constraint.latency_source) {
        slot.satisfied = false;
        slot.margin = 0;
      } else {
        slot.satisfied = latency.micros <= constraint.bound;
        slot.margin = constraint.bound - latency.micros;
      }
      break;
    }
    case ConstraintKind::MinBandwidthCapability: {
      std::int64_t bottleneck = 0;
      if (!path_bandwidth_capability(outer.candidate, outer.context.current.capability, bottleneck)) {
        slot.satisfied = false;
        slot.margin = 0;
      } else {
        slot.satisfied = bottleneck >= constraint.bound;
        slot.margin = bottleneck - constraint.bound;
      }
      break;
    }
    case ConstraintKind::MaxHopCount: {
      const auto hops = static_cast<std::int64_t>(outer.candidate.hop_count);
      slot.satisfied = hops <= constraint.bound;
      slot.margin = constraint.bound - hops;
      break;
    }
    case ConstraintKind::RequiredFailureDomainRelation: {
      const DomainScan scan = scan_domains(outer.candidate, constraint.domain_kind);
      if (!scan.complete) {
        slot.satisfied = false;
        slot.margin = 0;
      } else {
        const auto distinct = static_cast<std::int64_t>(scan.domains.size());
        slot.satisfied = distinct >= constraint.bound;
        slot.margin = distinct - constraint.bound;
      }
      break;
    }
    default:
      break;
  }
  return slot;
}

[[nodiscard]] std::uint64_t evidence_generation_of(const EvidenceGenerationSet& evidence,
                                                   EvidenceFamily family) noexcept {
  switch (family) {
    case EvidenceFamily::Topology: return evidence.topology.value();
    case EvidenceFamily::LinkState: return evidence.link_state.value();
    case EvidenceFamily::Capability: return evidence.capability.value();
    case EvidenceFamily::FailureDomain: return evidence.failure_domain.value();
    case EvidenceFamily::Policy: return evidence.policy.value();
    case EvidenceFamily::Planner: return evidence.planner.value();
    case EvidenceFamily::PathAuthority: return evidence.path_authority.value();
    case EvidenceFamily::ConstraintSet:
    case EvidenceFamily::None:
    default: return 0;
  }
}

[[nodiscard]] std::uint64_t required_generation_of(const EvidenceRequirements& required,
                                                   EvidenceFamily family) noexcept {
  switch (family) {
    case EvidenceFamily::Topology: return required.topology.value();
    case EvidenceFamily::LinkState: return required.link_state.value();
    case EvidenceFamily::Capability: return required.capability.value();
    case EvidenceFamily::FailureDomain: return required.failure_domain.value();
    case EvidenceFamily::Policy: return required.policy.value();
    case EvidenceFamily::Planner: return required.planner.value();
    case EvidenceFamily::PathAuthority: return required.path_authority.value();
    case EvidenceFamily::ConstraintSet:
    case EvidenceFamily::None:
    default: return 0;
  }
}

[[nodiscard]] ReasonCode staleness_code(EvidenceFamily family) noexcept {
  switch (family) {
    case EvidenceFamily::Topology: return ReasonCode::StaleTopologyEvidence;
    case EvidenceFamily::LinkState: return ReasonCode::StaleLinkStateEvidence;
    case EvidenceFamily::Capability: return ReasonCode::StaleCapabilityEvidence;
    case EvidenceFamily::FailureDomain: return ReasonCode::StaleFailureDomainEvidence;
    case EvidenceFamily::Policy: return ReasonCode::StalePolicyEvidence;
    case EvidenceFamily::Planner: return ReasonCode::StalePlannerEvidence;
    case EvidenceFamily::PathAuthority: return ReasonCode::StalePathAuthority;
    default: return ReasonCode::EvidenceNotBound;
  }
}

[[nodiscard]] Reason set_state_reason(const ConstraintSet& set, ReasonCode code) {
  Reason reason;
  reason.code = code;
  reason.reason_class = reason_class_of(code);
  reason.family = EvidenceFamily::ConstraintSet;
  reason.subject_kind = SubjectKind::ConstraintSet;
  reason.subject = set.id.value();
  reason.expected = static_cast<std::uint64_t>(set.generation.value());
  return reason;
}

[[nodiscard]] ReasonCode lifecycle_reason(ConstraintSetState state) noexcept {
  switch (state) {
    case ConstraintSetState::Declared: return ReasonCode::ConstraintSetNotActive;
    case ConstraintSetState::Active: return ReasonCode::None;
    case ConstraintSetState::Suspended: return ReasonCode::ConstraintSetSuspended;
    case ConstraintSetState::RevalidationRequired: return ReasonCode::ConstraintSetRevalidationRequired;
    case ConstraintSetState::Revoked: return ReasonCode::ConstraintSetRevoked;
    case ConstraintSetState::Superseded: return ReasonCode::ConstraintSetSuperseded;
    case ConstraintSetState::Retired: return ReasonCode::ConstraintSetRetired;
  }
  return ReasonCode::ConstraintSetNotFound;
}

[[nodiscard]] bool version_of(std::uint8_t verdict) noexcept { return verdict <= 2; }

}  // namespace

void canonicalize_reasons(std::vector<Reason>& reasons, const Limits& limits) {
  std::stable_sort(reasons.begin(), reasons.end(), reason_less);
  std::vector<Reason> kept;
  kept.reserve(reasons.size());
  std::set<ConstraintId> represented;
  for (const Reason& reason : reasons) {
    if (kept.size() >= limits.max_explanation_reasons) {
      break;
    }
    if (reason.constraint.is_valid() && !represented.count(reason.constraint)) {
      if (represented.size() >= limits.max_failed_constraints_per_evaluation) {
        continue;
      }
      represented.insert(reason.constraint);
    }
    kept.push_back(reason);
  }
  reasons = std::move(kept);
}

ReasonCode primary_reason_of(std::span<const Reason> reasons) noexcept {
  if (reasons.empty()) {
    return ReasonCode::None;
  }
  std::size_t best = 0;
  for (std::size_t index = 1; index < reasons.size(); ++index) {
    if (reason_less(reasons[index], reasons[best])) {
      best = index;
    }
  }
  return reasons[best].code;
}

Outcome outcome_from_reasons(std::span<const Reason> reasons, bool has_preferences) noexcept {
  if (reasons.empty()) {
    return has_preferences ? Outcome::AdmissibleWithPreferences : Outcome::Admissible;
  }
  return outcome_of(primary_reason_of(reasons));
}

Result<EvaluationRecord> evaluate_candidate(const EvaluationContext& context,
                                            const CandidatePath& candidate) {
  if (context.set == nullptr || context.limits == nullptr) {
    return Result<EvaluationRecord>::failure(ErrorCode::InvalidArgument,
                                             "evaluation context requires a set and a limit set");
  }
  const Limits& limits = *context.limits;
  std::string why;
  if (!validate_limits(limits, why)) {
    return Result<EvaluationRecord>::failure(ErrorCode::InvalidArgument, why);
  }

  EvaluationRecord record;
  record.set_id = context.set->id;
  record.set_generation = context.set->generation;
  record.path = candidate.path;
  record.authority_generation = candidate.authority_generation;
  record.generation = context.generation;
  record.provenance = context.provenance;
  record.evidence = candidate.evidence;
  record.committed_tick = context.now_tick;

  State state{*context.set, candidate, context, {}, {}, 0, false};

  // Stage 1: resource admission.
  if (context.set->constraints.size() > limits.max_constraints_per_set) {
    Reason reason;
    reason.code = ReasonCode::TooManyConstraints;
    reason.reason_class = ReasonClass::ResourceAdmission;
    reason.subject_kind = SubjectKind::ConstraintSet;
    reason.subject = context.set->id.value();
    reason.expected = limits.max_constraints_per_set;
    reason.actual = context.set->constraints.size();
    state.reasons.push_back(reason);
    state.truncated = false;
  }

  // Stage 2: wire/decode structural validation.
  if (state.reasons.empty()) {
    const Status set_status = verify_canonical_constraint_set(*context.set, limits);
    if (!set_status.ok()) {
      Reason reason;
      reason.code = ReasonCode::MalformedConstraint;
      reason.reason_class = ReasonClass::WireDecode;
      reason.subject_kind = SubjectKind::ConstraintSet;
      reason.subject = context.set->id.value();
      state.reasons.push_back(reason);
    }
    const Status candidate_status = validate_candidate(candidate, limits);
    if (!candidate_status.ok()) {
      Reason reason;
      reason.code = candidate_status.code() == ErrorCode::ResourceLimit
                        ? ReasonCode::TooManyEntityRefs
                        : ReasonCode::MalformedCandidate;
      reason.reason_class = reason_class_of(reason.code);
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    }
  }

  // Stage 3 and 4: caller identity, then epoch/boot/scope.
  if (state.reasons.empty() && !context.authority_verified) {
    const bool complete = context.provenance.epoch.is_valid() &&
                          context.provenance.publisher.is_valid() &&
                          context.provenance.worker_boot.is_valid() &&
                          context.provenance.attempt.is_valid();
    if (!complete) {
      Reason reason;
      reason.code = ReasonCode::MissingAuthorityContext;
      reason.reason_class = ReasonClass::CallerIdentity;
      reason.subject_kind = SubjectKind::Coordinator;
      state.reasons.push_back(reason);
    }
  }

  // Stage 5: constraint-set lifecycle and generation.
  if (state.reasons.empty()) {
    const ReasonCode lifecycle = lifecycle_reason(context.set->state);
    if (lifecycle != ReasonCode::None) {
      state.reasons.push_back(set_state_reason(*context.set, lifecycle));
    } else if (context.requested_set_generation.is_valid() &&
               context.requested_set_generation != context.set->generation) {
      Reason reason = set_state_reason(*context.set, ReasonCode::StaleConstraintSetGeneration);
      reason.expected = context.requested_set_generation.value();
      reason.actual = context.set->generation.value();
      state.reasons.push_back(reason);
    }
  }

  // Stage 6: Path Authority generation and verdict. This runtime never
  // overrides Path Authority: an illegal or unevaluated path is never
  // admissible, whatever the constraints say.
  if (state.reasons.empty()) {
    if (!candidate.authority_generation.is_valid()) {
      Reason reason;
      reason.code = ReasonCode::PathAuthorityGenerationMissing;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::PathAuthority;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    } else if (!context.current.path_authority.is_valid()) {
      Reason reason;
      reason.code = ReasonCode::EvidenceNotBound;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::PathAuthority;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    } else if (candidate.authority_generation != context.current.path_authority) {
      Reason reason;
      reason.code = ReasonCode::StalePathAuthority;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::PathAuthority;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      reason.expected = context.current.path_authority.value();
      reason.actual = candidate.authority_generation.value();
      state.reasons.push_back(reason);
    } else if (!version_of(static_cast<std::uint8_t>(candidate.authority_verdict))) {
      Reason reason;
      reason.code = ReasonCode::MalformedCandidate;
      reason.reason_class = reason_class_of(reason.code);
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    } else if (candidate.authority_verdict == PathAuthorityVerdict::NotEvaluated) {
      Reason reason;
      reason.code = ReasonCode::PathAuthorityNotEvaluated;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::PathAuthority;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    } else if (candidate.authority_verdict == PathAuthorityVerdict::Rejected) {
      Reason reason;
      reason.code = ReasonCode::PathNotLegal;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::PathAuthority;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      state.reasons.push_back(reason);
    }
  }

  // Evidence families actually consulted by this constraint set.
  // The Path Authority verdict is always consulted, so its generation is always
  // part of the currentness binding.
  state.consulted |= family_bit(EvidenceFamily::PathAuthority);
  for (const Constraint& constraint : context.set->constraints) {
    state.consulted |= families_of(constraint);
  }
  if (context.set->ranking.consume_planner_cost) {
    state.consulted |= family_bit(EvidenceFamily::Planner);
  }

  // Stage 7: mandatory evidence currentness, for consulted families only.
  if (state.reasons.empty() && state.consulted != 0) {
    const std::array<EvidenceFamily, 6> families = {
        EvidenceFamily::Topology,       EvidenceFamily::LinkState, EvidenceFamily::Capability,
        EvidenceFamily::FailureDomain,  EvidenceFamily::Policy,    EvidenceFamily::Planner};
    for (const EvidenceFamily family : families) {
      if ((state.consulted & family_bit(family)) == 0) {
        continue;
      }
      const std::uint64_t required = required_generation_of(context.current, family);
      const std::uint64_t actual = evidence_generation_of(candidate.evidence, family);
      if (required == 0) {
        Reason reason;
        reason.code = ReasonCode::EvidenceNotBound;
        reason.reason_class = reason_class_of(reason.code);
        reason.family = family;
        reason.subject_kind = SubjectKind::CandidatePath;
        reason.subject = candidate.path.value();
        state.reasons.push_back(reason);
        continue;
      }
      if (actual != required) {
        Reason reason;
        reason.code = staleness_code(family);
        reason.reason_class = reason_class_of(reason.code);
        reason.family = family;
        reason.subject_kind = SubjectKind::CandidatePath;
        reason.subject = candidate.path.value();
        reason.expected = required;
        reason.actual = actual;
        state.reasons.push_back(reason);
      }
    }
    if (context.current.max_evidence_age_ticks > 0 && candidate.evidence.captured_tick != 0 &&
        context.now_tick > candidate.evidence.captured_tick &&
        context.now_tick - candidate.evidence.captured_tick > context.current.max_evidence_age_ticks) {
      Reason reason;
      reason.code = ReasonCode::EvidenceAgeExceeded;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::ConstraintSet;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      reason.expected = context.current.max_evidence_age_ticks;
      reason.actual = context.now_tick - candidate.evidence.captured_tick;
      state.reasons.push_back(reason);
    }
    if (context.set->ranking.consume_planner_cost && candidate.has_planner_cost &&
        candidate.cost_model != context.set->ranking.expected_cost_model) {
      Reason reason;
      reason.code = ReasonCode::PlannerCostModelMismatch;
      reason.reason_class = reason_class_of(reason.code);
      reason.family = EvidenceFamily::Planner;
      reason.subject_kind = SubjectKind::CandidatePath;
      reason.subject = candidate.path.value();
      reason.expected = static_cast<std::uint64_t>(context.set->ranking.expected_cost_model);
      reason.actual = static_cast<std::uint64_t>(candidate.cost_model);
      state.reasons.push_back(reason);
    }
  }

  // Stage 8: mandatory constraints in canonical order.
  if (state.reasons.empty()) {
    for (std::uint32_t ordinal = 0; ordinal < context.set->constraints.size(); ++ordinal) {
      const Constraint& constraint = context.set->constraints[ordinal];
      if (constraint.scope != ConstraintScope::Mandatory) {
        continue;
      }
      evaluate_mandatory(constraint, ordinal, state);
    }
  }

  // Stage 9: preference evaluation. Preferences rank admissible candidates and
  // can never rescue a hard failure.
  if (state.reasons.empty()) {
    for (std::uint32_t ordinal = 0; ordinal < context.set->constraints.size(); ++ordinal) {
      const Constraint& constraint = context.set->constraints[ordinal];
      if (constraint.scope != ConstraintScope::Preference) {
        continue;
      }
      state.preferences.push_back(evaluate_preference(constraint, ordinal, state));
    }
    std::stable_sort(state.preferences.begin(), state.preferences.end(),
                     [](const PreferenceSlot& a, const PreferenceSlot& b) {
                       if (a.rank != b.rank) return a.rank < b.rank;
                       return a.constraint_ordinal < b.constraint_ordinal;
                     });
  }

  const std::size_t produced = state.reasons.size();
  canonicalize_reasons(state.reasons, limits);
  record.reasons_truncated = state.truncated || state.reasons.size() < produced;
  record.reasons = std::move(state.reasons);
  record.preferences = std::move(state.preferences);
  record.consulted = state.consulted;
  record.primary_reason = primary_reason_of(record.reasons);
  record.outcome = outcome_from_reasons(record.reasons, !record.preferences.empty());
  record.id = derived_evaluation_id(record.set_id, record.set_generation, record.path,
                                    record.authority_generation, record.evidence);
  record.digest = evaluation_digest(record);
  return Result<EvaluationRecord>::success(std::move(record));
}

Result<EvaluationBatch> evaluate_batch(const EvaluationContext& context,
                                       std::span<const CandidatePath> candidates) {
  EvaluationBatch batch;
  if (context.set == nullptr || context.limits == nullptr) {
    return Result<EvaluationBatch>::failure(ErrorCode::InvalidArgument,
                                            "evaluation context requires a set and a limit set");
  }
  const Limits& limits = *context.limits;
  batch.set_id = context.set->id;
  batch.set_generation = context.set->generation;
  batch.generation = context.generation;

  if (candidates.size() > limits.max_candidates_per_evaluation) {
    batch.batch_outcome = BatchOutcome::BatchRejected;
    batch.primary_batch_reason = ReasonCode::TooManyCandidates;
    return Result<EvaluationBatch>::success(std::move(batch));
  }
  if (candidates.size() > limits.max_batch_size) {
    batch.batch_outcome = BatchOutcome::BatchRejected;
    batch.primary_batch_reason = ReasonCode::BatchTooLarge;
    return Result<EvaluationBatch>::success(std::move(batch));
  }

  std::vector<CandidatePath> ordered(candidates.begin(), candidates.end());
  std::stable_sort(ordered.begin(), ordered.end(), candidate_canonical_less);

  // Duplicate candidate identity with different content is a caller error: the
  // population is rejected rather than silently reduced.
  for (std::size_t index = 1; index < ordered.size(); ++index) {
    if (ordered[index - 1].path == ordered[index].path) {
      const bool identical = candidate_digest(ordered[index - 1]) == candidate_digest(ordered[index]);
      if (!identical) {
        batch.batch_outcome = BatchOutcome::BatchRejected;
        batch.primary_batch_reason = ReasonCode::MalformedCandidate;
        return Result<EvaluationBatch>::success(std::move(batch));
      }
    }
  }

  std::vector<CandidatePath> canonical;
  canonical.reserve(ordered.size());
  for (const CandidatePath& candidate : ordered) {
    if (!canonical.empty() && canonical.back().path == candidate.path) {
      continue;
    }
    canonical.push_back(candidate);
  }

  batch.records.reserve(canonical.size());
  for (const CandidatePath& candidate : canonical) {
    Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
    if (!record.ok()) {
      return Result<EvaluationBatch>::failure(record.code(), record.detail());
    }
    batch.records.push_back(std::move(record.value()));
  }

  batch.admissible_order = order_admissible(batch.records, canonical, context.set->ranking);
  batch.has_admissible = !batch.admissible_order.empty();
  batch.batch_outcome =
      batch.has_admissible ? BatchOutcome::AdmissibleCandidatesAvailable : BatchOutcome::NoAdmissibleCandidate;
  if (!batch.has_admissible && !batch.records.empty()) {
    ReasonCode primary = batch.records.front().primary_reason;
    for (const EvaluationRecord& record : batch.records) {
      if (record.primary_reason != ReasonCode::None &&
          reason_class_of(record.primary_reason) < reason_class_of(primary)) {
        primary = record.primary_reason;
      } else if (reason_class_of(record.primary_reason) == reason_class_of(primary) &&
                 record.primary_reason < primary) {
        primary = record.primary_reason;
      }
    }
    batch.primary_batch_reason = primary;
  }
  return Result<EvaluationBatch>::success(std::move(batch));
}

}  // namespace crf
