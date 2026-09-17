// Constraint Routing Fabric -- shared deterministic test fixtures.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic only. Every value here is fabricated for validation: nothing in
// this header is evidence about a real network.
#ifndef CONSTRAINT_ROUTING_FABRIC_TEST_FIXTURE_HPP
#define CONSTRAINT_ROUTING_FABRIC_TEST_FIXTURE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "constraint_routing_fabric/fabric.hpp"

namespace crf::fixture {

[[nodiscard]] inline ConstraintId cid(std::uint64_t value) { return ConstraintId::from_value(value); }
[[nodiscard]] inline NodeId nid(std::uint64_t value) { return NodeId::from_value(value); }
[[nodiscard]] inline LinkId lid(std::uint64_t value) { return LinkId::from_value(value); }
[[nodiscard]] inline TierId tid(std::uint64_t value) { return TierId::from_value(value); }
[[nodiscard]] inline SiteId sid(std::uint64_t value) { return SiteId::from_value(value); }
[[nodiscard]] inline CapabilityId capid(std::uint64_t value) { return CapabilityId::from_value(value); }
[[nodiscard]] inline PolicyId pid(std::uint64_t value) { return PolicyId::from_value(value); }
[[nodiscard]] inline PathId pathid(std::uint64_t value) { return PathId::from_value(value); }
[[nodiscard]] inline ConstraintSetId setid(std::uint64_t value) {
  return ConstraintSetId::from_value(value);
}
[[nodiscard]] inline LocalityDomainId locality(std::uint64_t value) {
  return LocalityDomainId::from_value(value);
}
[[nodiscard]] inline FailureDomainId domain(std::uint64_t value) {
  return FailureDomainId::from_value(value);
}
[[nodiscard]] inline IsolationClassId isolation_class(std::uint64_t value) {
  return IsolationClassId::from_value(value);
}

/// The authoritative evidence generations every fixture binds.
[[nodiscard]] inline EvidenceRequirements standard_evidence() {
  EvidenceRequirements evidence;
  evidence.topology = TopologyGeneration::from_value(3);
  evidence.link_state = LinkStateGeneration::from_value(4);
  evidence.capability = CapabilityGeneration::from_value(5);
  evidence.failure_domain = FailureDomainGeneration::from_value(6);
  evidence.policy = PolicyGeneration::from_value(7);
  evidence.planner = PlannerGeneration::from_value(8);
  evidence.path_authority = PathAuthorityGeneration::from_value(9);
  evidence.max_evidence_age_ticks = 0;
  return evidence;
}

[[nodiscard]] inline EvidenceGenerationSet evidence_binding(const EvidenceRequirements& evidence) {
  EvidenceGenerationSet binding;
  binding.topology = evidence.topology;
  binding.link_state = evidence.link_state;
  binding.capability = evidence.capability;
  binding.failure_domain = evidence.failure_domain;
  binding.policy = evidence.policy;
  binding.planner = evidence.planner;
  binding.path_authority = evidence.path_authority;
  binding.consulted = 0;
  binding.captured_tick = 100;
  return binding;
}

// --- constraint factories ---------------------------------------------------

[[nodiscard]] inline Constraint base(ConstraintId id, ConstraintKind kind,
                                     ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint;
  constraint.id = id;
  constraint.generation = ConstraintGeneration::from_value(1);
  constraint.kind = kind;
  constraint.scope = scope;
  return constraint;
}

[[nodiscard]] inline Constraint max_latency(ConstraintId id, LatencySource source,
                                            std::int64_t micros,
                                            ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::MaxLatency, scope);
  constraint.latency_source = source;
  constraint.bound = micros;
  return constraint;
}

[[nodiscard]] inline Constraint max_hops(ConstraintId id, std::int64_t hops,
                                         ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::MaxHopCount, scope);
  constraint.bound = hops;
  return constraint;
}

[[nodiscard]] inline Constraint min_bandwidth(ConstraintId id, std::int64_t bits_per_second,
                                              ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::MinBandwidthCapability, scope);
  constraint.bound = bits_per_second;
  return constraint;
}

[[nodiscard]] inline Constraint with_nodes(ConstraintId id, ConstraintKind kind,
                                           std::vector<NodeId> nodes,
                                           ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, kind, scope);
  constraint.nodes = std::move(nodes);
  return constraint;
}

[[nodiscard]] inline Constraint with_links(ConstraintId id, ConstraintKind kind,
                                           std::vector<LinkId> links,
                                           ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, kind, scope);
  constraint.links = std::move(links);
  return constraint;
}

[[nodiscard]] inline Constraint with_tiers(ConstraintId id, ConstraintKind kind,
                                           std::vector<TierId> tiers,
                                           ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, kind, scope);
  constraint.tiers = std::move(tiers);
  return constraint;
}

[[nodiscard]] inline Constraint with_sites(ConstraintId id, ConstraintKind kind,
                                           std::vector<SiteId> sites,
                                           ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, kind, scope);
  constraint.sites = std::move(sites);
  return constraint;
}

[[nodiscard]] inline Constraint with_capabilities(ConstraintId id, ConstraintKind kind,
                                                  std::vector<CapabilityId> capabilities,
                                                  ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, kind, scope);
  constraint.capabilities = std::move(capabilities);
  return constraint;
}

[[nodiscard]] inline Constraint with_policies(ConstraintId id, std::vector<PolicyId> policies,
                                              ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::AdministrativePolicy, scope);
  constraint.policies = std::move(policies);
  return constraint;
}

[[nodiscard]] inline Constraint locality_scope(ConstraintId id, DomainKind kind,
                                               LocalityDomainId locality_domain,
                                               ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::LocalityScope, scope);
  constraint.domain_kind = kind;
  constraint.locality_domain = locality_domain;
  return constraint;
}

[[nodiscard]] inline Constraint isolation_required(ConstraintId id, IsolationClassId cls,
                                                   ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::IsolationClass, scope);
  constraint.isolation_class = cls;
  return constraint;
}

[[nodiscard]] inline Constraint required_domain_distinct(
    ConstraintId id, DomainKind kind, std::int64_t count,
    ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::RequiredFailureDomainRelation, scope);
  constraint.domain_kind = kind;
  constraint.domain_relation = DomainRelation::Distinct;
  constraint.bound = count;
  return constraint;
}

[[nodiscard]] inline Constraint forbidden_domain_shared(
    ConstraintId id, DomainKind kind, ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::ForbiddenFailureDomainRelation, scope);
  constraint.domain_kind = kind;
  constraint.domain_relation = DomainRelation::Shared;
  return constraint;
}

[[nodiscard]] inline Constraint forbidden_domain_distinct(
    ConstraintId id, DomainKind kind, std::int64_t count,
    ConstraintScope scope = ConstraintScope::Mandatory) {
  Constraint constraint = base(id, ConstraintKind::ForbiddenFailureDomainRelation, scope);
  constraint.domain_kind = kind;
  constraint.domain_relation = DomainRelation::Distinct;
  constraint.bound = count;
  return constraint;
}

inline void as_preference(Constraint& constraint, std::uint32_t rank, std::uint32_t weight) {
  constraint.scope = ConstraintScope::Preference;
  constraint.preference_rank = rank;
  constraint.preference_weight = weight;
}

// --- candidate fixture ------------------------------------------------------

struct PathSpec {
  PathId path{};
  std::vector<NodeId> nodes{};
  std::uint64_t first_link{1000};
  TierId tier{};
  SiteId site{};
  std::vector<LocalityRef> localities{};
  std::vector<FailureDomainRef> domains{};
  std::vector<CapabilityId> capabilities{};
  std::vector<IsolationClassId> isolation_classes{};
  std::vector<PolicyId> policies{};
  std::int64_t planner_latency_micros{0};
  std::int64_t observed_latency_micros{0};
  std::int64_t bandwidth_bits_per_second{0};
  PlannerGeneration planner_generation{};
  PathAuthorityGeneration authority_generation{};
  PathAuthorityVerdict verdict{PathAuthorityVerdict::Legal};
  bool has_planner_rank{false};
  std::uint32_t planner_rank{0};
  bool has_planner_cost{false};
  std::int64_t planner_cost{0};
  PlannerCostModel cost_model{PlannerCostModel::None};
  std::uint64_t captured_tick{100};
};

/// Builds a well-formed candidate from a specification. Synthetic evidence is
/// labelled as such; authority generations default to the standard fixture.
[[nodiscard]] inline CandidatePath build_candidate(const PathSpec& spec,
                                                   const EvidenceRequirements& evidence) {
  CandidatePath candidate;
  candidate.path = spec.path;
  candidate.authority_generation = spec.authority_generation.is_valid()
                                       ? spec.authority_generation
                                       : evidence.path_authority;
  candidate.authority_verdict = spec.verdict;
  candidate.planner_generation =
      spec.planner_generation.is_valid() ? spec.planner_generation : evidence.planner;
  candidate.has_planner_rank = spec.has_planner_rank;
  candidate.planner_rank = spec.planner_rank;
  candidate.has_planner_cost = spec.has_planner_cost;
  candidate.planner_cost = spec.planner_cost;
  candidate.cost_model = spec.cost_model;
  candidate.evidence = evidence_binding(evidence);
  candidate.evidence.captured_tick = spec.captured_tick;
  // The candidate's own binding must agree with the identities it carries.
  candidate.evidence.path_authority = candidate.authority_generation;
  candidate.evidence.planner = candidate.planner_generation;

  for (std::size_t index = 0; index < spec.nodes.size(); ++index) {
    NodeFact node;
    node.node = spec.nodes[index];
    node.tier = spec.tier;
    node.site = spec.site;
    node.localities = spec.localities;
    node.domains = spec.domains;
    for (const CapabilityId& capability : spec.capabilities) {
      node.capabilities.push_back(CapabilityRef{capability, evidence.capability});
    }
    for (const IsolationClassId& cls : spec.isolation_classes) {
      node.isolation.push_back(IsolationAttestation{cls, evidence.failure_domain});
    }
    candidate.nodes.push_back(std::move(node));
  }
  for (std::size_t index = 0; index + 1 < spec.nodes.size(); ++index) {
    LinkFact link;
    link.link = lid(spec.first_link + index);
    link.endpoints[0] = spec.nodes[index];
    link.endpoints[1] = spec.nodes[index + 1];
    if (spec.bandwidth_bits_per_second != 0) {
      link.bandwidth.model = CapabilityModel::DeclaredCapabilityRegistry;
      link.bandwidth.provenance = EvidenceProvenance::FabricCapabilityRegistry;
      link.bandwidth.bits_per_second = spec.bandwidth_bits_per_second;
      link.bandwidth.generation = evidence.capability;
      link.bandwidth.observed_tick = spec.captured_tick;
    }
    link.domains = spec.domains;
    for (const CapabilityId& capability : spec.capabilities) {
      link.capabilities.push_back(CapabilityRef{capability, evidence.capability});
    }
    for (const IsolationClassId& cls : spec.isolation_classes) {
      link.isolation.push_back(IsolationAttestation{cls, evidence.failure_domain});
    }
    candidate.links.push_back(std::move(link));
  }
  candidate.hop_count = static_cast<std::uint32_t>(candidate.links.size());

  if (spec.planner_latency_micros != 0) {
    candidate.latency.source = LatencySource::PlannerCost;
    candidate.latency.provenance = EvidenceProvenance::PlannerModel;
    candidate.latency.micros = spec.planner_latency_micros;
    candidate.latency.planner_generation = evidence.planner;
  } else if (spec.observed_latency_micros != 0) {
    candidate.latency.source = LatencySource::ObservedLatency;
    candidate.latency.provenance = EvidenceProvenance::SyntheticFixture;
    candidate.latency.micros = spec.observed_latency_micros;
    candidate.latency.observed_generation = evidence.link_state;
    candidate.latency.observed_tick = spec.captured_tick;
  }

  for (const PolicyId& policy : spec.policies) {
    candidate.policies.push_back(PolicyAttestation{policy, evidence.policy});
  }
  return candidate;
}

/// Builds, canonicalizes and finalizes a constraint set. Aborts the caller's
/// expectation when the fixture itself is invalid, so tests never silently
/// validate a broken fixture.
[[nodiscard]] inline ConstraintSet make_set(ConstraintSetId id, std::vector<Constraint> constraints,
                                            const EvidenceRequirements& evidence,
                                            RankingPolicy ranking = {}) {
  ConstraintSet set;
  set.id = id;
  set.generation = ConstraintSetGeneration::from_value(1);
  set.state = ConstraintSetState::Active;
  set.constraints = std::move(constraints);
  set.evidence = evidence;
  set.ranking = ranking;
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status = validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
  if (!status.ok()) {
    set.name = "INVALID FIXTURE: " + std::string(to_string(status.code()));
  }
  return set;
}

/// A stable default limit set for fixture contexts.
[[nodiscard]] inline const Limits& default_limits() {
  static const Limits limits{};
  return limits;
}

[[nodiscard]] inline AuthorityScopeMask all_scopes() {
  return scope_bit(AuthorityScope::PublishConstraintSet) |
         scope_bit(AuthorityScope::PublishEvaluation) |
         scope_bit(AuthorityScope::ApplyLifecycle) |
         scope_bit(AuthorityScope::ReadDefinitions) |
         scope_bit(AuthorityScope::ReadResults) |
         scope_bit(AuthorityScope::RegisterPublisher) |
         scope_bit(AuthorityScope::AdministerFencing);
}

/// A coordinator with one registered publisher and a deterministic clock.
struct CoordinatorHarness {
  ManualClock clock{1000};
  std::unique_ptr<Coordinator> coordinator{};
  PublisherId publisher{PublisherId::from_value(1)};
  WorkerBootId boot{WorkerBootId::from_value(4242)};
  SessionId session{SessionId::from_value(7)};
  AuthorityScopeMask scopes{0};
  std::uint64_t attempts{0};

  [[nodiscard]] AuthorityContext next_context() {
    ++attempts;
    AuthorityContext context;
    context.epoch = coordinator->epoch();
    context.publisher = publisher;
    context.worker_boot = boot;
    context.session = session;
    context.scopes = scopes;
    context.attempt = MutationAttemptId::from_value(1000 + attempts);
    context.request = RequestId::from_value(attempts);
    return context;
  }
};

/// Opens an in-memory coordinator by default, or a durable one when a store
/// path is given. Registers the fixture publisher with the full scope set.
[[nodiscard]] inline Result<std::unique_ptr<CoordinatorHarness>> make_harness(
    const std::string& store_path = std::string(), Limits limits = Limits{},
    WorkerBootId boot = WorkerBootId::from_value(4242)) {
  auto harness = std::make_unique<CoordinatorHarness>();
  harness->boot = boot;
  CoordinatorConfig config;
  config.limits = limits;
  config.store_path = store_path;
  config.allow_initialize = true;
  config.evidence = standard_evidence();
  PublisherGrant grant;
  grant.publisher = PublisherId::from_value(1);
  grant.scopes = all_scopes();
  config.grants.push_back(grant);
  Result<std::unique_ptr<Coordinator>> coordinator = Coordinator::open(config, &harness->clock);
  if (!coordinator.ok()) {
    return Result<std::unique_ptr<CoordinatorHarness>>::failure(coordinator.code(),
                                                                coordinator.detail());
  }
  harness->coordinator = std::move(coordinator.value());
  AuthorityContext registration;
  registration.epoch = harness->coordinator->epoch();
  registration.publisher = harness->publisher;
  registration.worker_boot = harness->boot;
  registration.session = harness->session;
  registration.attempt = MutationAttemptId::from_value(1);
  registration.request = RequestId::from_value(1);
  const Result<PublisherRegistration> registered = harness->coordinator->register_publisher(
      registration, harness->publisher, harness->boot, all_scopes(), harness->session);
  if (!registered.ok()) {
    return Result<std::unique_ptr<CoordinatorHarness>>::failure(registered.code(),
                                                                registered.detail());
  }
  harness->scopes = registered.value().scopes;
  return Result<std::unique_ptr<CoordinatorHarness>>::success(std::move(harness));
}

[[nodiscard]] inline EvaluationContext context_for(const ConstraintSet& set,
                                                   const EvidenceRequirements& evidence,
                                                   EvaluationGeneration generation = {}) {
  EvaluationContext context;
  context.set = &set;
  context.current = evidence;
  context.limits = &default_limits();
  context.generation = generation.is_valid() ? generation : EvaluationGeneration::from_value(1);
  context.now_tick = 1000;
  context.provenance.epoch = CoordinatorEpoch::from_value(1);
  context.provenance.publisher = PublisherId::from_value(1);
  context.provenance.worker_boot = WorkerBootId::from_value(1);
  context.provenance.attempt = MutationAttemptId::from_value(1);
  context.provenance.request = RequestId::from_value(1);
  context.authority_verified = true;
  return context;
}

}  // namespace crf::fixture

#endif  // CONSTRAINT_ROUTING_FABRIC_TEST_FIXTURE_HPP
