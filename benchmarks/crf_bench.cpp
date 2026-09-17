// Constraint Routing Fabric -- deterministic scale benchmarks.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The scale benchmark measures the throughput of the hot deterministic paths.
// It is not a test: it reports and exits 0 unless a benchmark cannot run at all.
//
// Stable, machine-readable output (no addresses, thread ids, timestamps or
// container iteration order):
//   bench <name> <units> <count> <milliseconds> <items_per_second>
//   bench_admissible <name> <size> <evaluated> <admissible>
//   bench_bytes <name> <size> <bytes>
//   bench_deterministic <yes|no>
//   bench_total <milliseconds>
//   bench_error <name> <detail>
//
// std::chrono::steady_clock is used for measurement only: no decision in this
// file depends on a clock reading. Every fixture is derived from fixed
// constants, so two runs perform exactly the same work.
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/evaluator.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/ordering.hpp"
#include "constraint_routing_fabric/persistence.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace {

using SteadyClock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Scale points
// ---------------------------------------------------------------------------
// Each benchmark runs at three sizes chosen so that the whole run stays well
// under a minute on a modern x64 machine while still showing its growth curve.
constexpr std::size_t kScaleCount = 3;
constexpr const char* kScaleNames[kScaleCount] = {"small", "medium", "large"};

constexpr std::size_t kSetScaleConstraints[kScaleCount] = {18, 72, 200};
constexpr std::size_t kSetScaleIterations[kScaleCount] = {200, 400, 600};
constexpr std::size_t kCandidateScaleCounts[kScaleCount] = {400, 1600, 6400};
constexpr std::size_t kBatchScalePopulations[kScaleCount] = {8, 32, 64};
constexpr std::size_t kBatchScaleRepeats[kScaleCount] = {64, 64, 64};
constexpr std::size_t kOrderScaleRepeats[kScaleCount] = {2000, 1000, 500};
constexpr std::size_t kDigestScaleCandidates[kScaleCount] = {200, 1000, 4000};
constexpr std::size_t kDigestScaleSetRepeats = 32;
constexpr std::size_t kPersistenceScaleRepeats[kScaleCount] = {200, 100, 50};
constexpr std::size_t kDurableScaleRepeats[kScaleCount] = {3, 2, 1};
constexpr std::size_t kContradictionScaleRepeats[kScaleCount] = {2000, 4000, 8000};
constexpr std::size_t kPersistedEvaluationCounts[kScaleCount] = {8, 32, 64};

constexpr crf::Limits kLimits{};

// The scale points must stay inside the default limits: a benchmark that asked
// for more than the runtime admits would measure a rejection path instead of the
// pipeline it is named after.
static_assert(kSetScaleConstraints[kScaleCount - 1] <=
                  static_cast<std::size_t>(kLimits.max_constraints_per_set),
              "the largest set scale must fit the constraint limit");
static_assert(kBatchScalePopulations[kScaleCount - 1] <=
                  static_cast<std::size_t>(kLimits.max_candidates_per_evaluation),
              "the largest batch scale must fit the candidate limit");
static_assert(kPersistedEvaluationCounts[kScaleCount - 1] <=
                  static_cast<std::size_t>(kLimits.max_evaluations_retained),
              "the persisted evaluation count must fit the retention limit");

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
/// Accumulates every measured result so no benchmark body can be optimized away.
volatile std::uint64_t g_sink = 0;
bool g_failed = false;

[[nodiscard]] std::uint64_t nanos_to_millis(std::uint64_t nanos) noexcept {
  return nanos / 1000000ull;
}

[[nodiscard]] std::uint64_t nanos_to_millis_fraction(std::uint64_t nanos) noexcept {
  return (nanos % 1000000ull) / 1000ull;
}

void print_throughput(const char* name, const char* units, std::uint64_t count, std::uint64_t nanos) {
  const std::uint64_t per_second = nanos == 0 ? 0 : (count * 1000000000ull) / nanos;
  std::printf("bench %s %s %llu %llu.%03llu %llu\n", name, units,
              static_cast<unsigned long long>(count),
              static_cast<unsigned long long>(nanos_to_millis(nanos)),
              static_cast<unsigned long long>(nanos_to_millis_fraction(nanos)),
              static_cast<unsigned long long>(per_second));
  std::fflush(stdout);
}

void print_bytes(const char* name, const char* size, std::uint64_t bytes) {
  std::printf("bench_bytes %s %s %llu\n", name, size, static_cast<unsigned long long>(bytes));
  std::fflush(stdout);
}

void print_admissible(const char* name, const char* size, std::uint64_t evaluated,
                      std::uint64_t admissible) {
  std::printf("bench_admissible %s %s %llu %llu\n", name, size,
              static_cast<unsigned long long>(evaluated),
              static_cast<unsigned long long>(admissible));
  std::fflush(stdout);
}

void report_error(const char* name, const std::string& detail) {
  g_failed = true;
  std::printf("bench_error %s %s\n", name, detail.c_str());
  std::fflush(stdout);
}

/// Measures elapsed steady time. Used only around benchmark bodies.
class Stopwatch {
 public:
  Stopwatch() noexcept : start_(SteadyClock::now()) {}

  [[nodiscard]] std::uint64_t elapsed_nanos() const noexcept {
    const SteadyClock::duration elapsed = SteadyClock::now() - start_;
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
  }

 private:
  SteadyClock::time_point start_;
};

// ---------------------------------------------------------------------------
// Fixture constants
// ---------------------------------------------------------------------------
// Every identity and generation below is fixed, so the fixtures are identical
// on every run and on every machine.
constexpr std::uint64_t kTopologyGenerationValue = 11;
constexpr std::uint64_t kLinkStateGenerationValue = 12;
constexpr std::uint64_t kCapabilityGenerationValue = 13;
constexpr std::uint64_t kFailureDomainGenerationValue = 14;
constexpr std::uint64_t kPolicyGenerationValue = 15;
constexpr std::uint64_t kPlannerGenerationValue = 16;
constexpr std::uint64_t kPathAuthorityGenerationValue = 7;

constexpr crf::ConstraintSetId kSyntheticSetId = crf::ConstraintSetId::from_value(0x2b01ull);
constexpr crf::ConstraintSetId kEvaluationSetId = crf::ConstraintSetId::from_value(0x2b02ull);
constexpr crf::ConstraintSetGeneration kSetGeneration = crf::ConstraintSetGeneration::from_value(5);

constexpr crf::NodeId kAnchorNodeA = crf::NodeId::from_value(1001);
constexpr crf::NodeId kAnchorNodeB = crf::NodeId::from_value(1002);
constexpr crf::LinkId kAnchorLinkA = crf::LinkId::from_value(2001);
constexpr crf::LinkId kAnchorLinkB = crf::LinkId::from_value(2002);
constexpr crf::TierId kTierA = crf::TierId::from_value(3001);
constexpr crf::TierId kTierB = crf::TierId::from_value(3002);
constexpr crf::SiteId kSiteA = crf::SiteId::from_value(4001);
constexpr crf::SiteId kSiteB = crf::SiteId::from_value(4002);
constexpr crf::LocalityDomainId kRackDomain = crf::LocalityDomainId::from_value(4101);
constexpr crf::LocalityDomainId kPlaneLocality = crf::LocalityDomainId::from_value(4102);
constexpr crf::FailureDomainId kDomainA = crf::FailureDomainId::from_value(4201);
constexpr crf::FailureDomainId kDomainB = crf::FailureDomainId::from_value(4202);
constexpr crf::FailureDomainId kPlaneFailureDomain = crf::FailureDomainId::from_value(4203);
constexpr crf::CapabilityId kCapability = crf::CapabilityId::from_value(4301);
constexpr crf::CapabilityId kSecondaryCapability = crf::CapabilityId::from_value(4302);
constexpr crf::PolicyId kPolicy = crf::PolicyId::from_value(4401);
constexpr crf::PolicyId kSecondaryPolicy = crf::PolicyId::from_value(4402);
constexpr crf::IsolationClassId kIsolationClass = crf::IsolationClassId::from_value(4501);
constexpr crf::IsolationClassId kSecondaryIsolationClass = crf::IsolationClassId::from_value(4502);

/// Identities that no fixture ever uses, so the forbidden constraints pass.
constexpr std::uint64_t kAbsentNode = 900001;
constexpr std::uint64_t kAbsentLink = 900002;
constexpr std::uint64_t kAbsentTier = 900003;
constexpr std::uint64_t kAbsentSite = 900004;
constexpr std::uint64_t kAbsentCapability = 900005;

constexpr crf::EvidenceFamilyMask kAllFamilies =
    crf::family_bit(crf::EvidenceFamily::Topology) | crf::family_bit(crf::EvidenceFamily::LinkState) |
    crf::family_bit(crf::EvidenceFamily::Capability) |
    crf::family_bit(crf::EvidenceFamily::FailureDomain) |
    crf::family_bit(crf::EvidenceFamily::Policy) | crf::family_bit(crf::EvidenceFamily::Planner) |
    crf::family_bit(crf::EvidenceFamily::PathAuthority);

[[nodiscard]] crf::EvidenceRequirements default_evidence() {
  crf::EvidenceRequirements evidence;
  evidence.topology = crf::TopologyGeneration::from_value(kTopologyGenerationValue);
  evidence.link_state = crf::LinkStateGeneration::from_value(kLinkStateGenerationValue);
  evidence.capability = crf::CapabilityGeneration::from_value(kCapabilityGenerationValue);
  evidence.failure_domain = crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue);
  evidence.policy = crf::PolicyGeneration::from_value(kPolicyGenerationValue);
  evidence.planner = crf::PlannerGeneration::from_value(kPlannerGenerationValue);
  evidence.path_authority = crf::PathAuthorityGeneration::from_value(kPathAuthorityGenerationValue);
  evidence.max_evidence_age_ticks = 0;
  return evidence;
}

// ---------------------------------------------------------------------------
// Constraint fixtures
// ---------------------------------------------------------------------------
constexpr std::size_t kConstraintKindCount = 18;

constexpr crf::ConstraintKind kAllKinds[kConstraintKindCount] = {
    crf::ConstraintKind::MaxLatency,
    crf::ConstraintKind::MinBandwidthCapability,
    crf::ConstraintKind::RequiredNode,
    crf::ConstraintKind::ForbiddenNode,
    crf::ConstraintKind::RequiredLink,
    crf::ConstraintKind::ForbiddenLink,
    crf::ConstraintKind::RequiredTier,
    crf::ConstraintKind::ForbiddenTier,
    crf::ConstraintKind::RequiredSite,
    crf::ConstraintKind::ForbiddenSite,
    crf::ConstraintKind::LocalityScope,
    crf::ConstraintKind::IsolationClass,
    crf::ConstraintKind::RequiredCapability,
    crf::ConstraintKind::ForbiddenCapability,
    crf::ConstraintKind::RequiredFailureDomainRelation,
    crf::ConstraintKind::ForbiddenFailureDomainRelation,
    crf::ConstraintKind::AdministrativePolicy,
    crf::ConstraintKind::MaxHopCount,
};

/// Kinds whose multiplicity inside one set is constrained by the contradiction
/// algebra: at most one locality scope per kind, one isolation class and one
/// failure-domain relation pair. They appear once per synthetic set.
constexpr std::size_t kRepeatableKindCount = 14;
constexpr std::size_t kRepeatableKindSlots[kRepeatableKindCount] = {0, 1, 2,  3,  4,  5,  6,
                                                                    7, 8, 9, 12, 13, 16, 17};

[[nodiscard]] crf::Constraint make_mandatory(crf::ConstraintKind kind, std::uint64_t id) {
  crf::Constraint constraint;
  constraint.id = crf::ConstraintId::from_value(100 + id);
  constraint.generation = crf::ConstraintGeneration::from_value(1);
  constraint.kind = kind;
  constraint.scope = crf::ConstraintScope::Mandatory;
  constraint.unknown_policy = crf::UnknownPolicy::FailClosed;
  return constraint;
}

/// Builds the \p slot-th constraint of the synthetic mix. Every payload field
/// is derived from \p serial so no two generated constraints are equivalent.
[[nodiscard]] crf::Constraint make_synthetic_constraint(std::size_t slot, std::uint64_t serial) {
  const crf::ConstraintKind kind = kAllKinds[slot % kConstraintKindCount];
  crf::Constraint constraint = make_mandatory(kind, serial);
  switch (kind) {
    case crf::ConstraintKind::MaxLatency:
      constraint.latency_source = crf::LatencySource::PlannerCost;
      constraint.bound = 1000 + static_cast<std::int64_t>(serial);
      break;
    case crf::ConstraintKind::MinBandwidthCapability:
      constraint.bound = 1000000 + static_cast<std::int64_t>(serial);
      break;
    case crf::ConstraintKind::MaxHopCount:
      // Larger than the distinct required-node count of any generated set, so
      // the set never contradicts itself. The serial keeps every generated hop
      // budget distinct, so nothing collapses as an equivalent duplicate.
      constraint.bound = 32 + static_cast<std::int64_t>(serial % 4096);
      break;
    case crf::ConstraintKind::RequiredNode:
      constraint.nodes.push_back(crf::NodeId::from_value(100000 + serial));
      break;
    case crf::ConstraintKind::ForbiddenNode:
      constraint.nodes.push_back(crf::NodeId::from_value(200000 + serial));
      break;
    case crf::ConstraintKind::RequiredLink:
      constraint.links.push_back(crf::LinkId::from_value(300000 + serial));
      break;
    case crf::ConstraintKind::ForbiddenLink:
      constraint.links.push_back(crf::LinkId::from_value(400000 + serial));
      break;
    case crf::ConstraintKind::RequiredTier:
      constraint.tiers.push_back(crf::TierId::from_value(500000 + serial));
      break;
    case crf::ConstraintKind::ForbiddenTier:
      constraint.tiers.push_back(crf::TierId::from_value(600000 + serial));
      break;
    case crf::ConstraintKind::RequiredSite:
      constraint.sites.push_back(crf::SiteId::from_value(700000 + serial));
      break;
    case crf::ConstraintKind::ForbiddenSite:
      constraint.sites.push_back(crf::SiteId::from_value(800000 + serial));
      break;
    case crf::ConstraintKind::LocalityScope:
      constraint.domain_kind = crf::DomainKind::Rack;
      constraint.locality_domain = kRackDomain;
      break;
    case crf::ConstraintKind::IsolationClass:
      constraint.isolation_class = kIsolationClass;
      break;
    case crf::ConstraintKind::RequiredCapability:
      constraint.capabilities.push_back(crf::CapabilityId::from_value(900000 + serial));
      break;
    case crf::ConstraintKind::ForbiddenCapability:
      constraint.capabilities.push_back(crf::CapabilityId::from_value(1000000 + serial));
      break;
    case crf::ConstraintKind::RequiredFailureDomainRelation:
      constraint.domain_kind = crf::DomainKind::Rack;
      constraint.domain_relation = crf::DomainRelation::Distinct;
      constraint.bound = 1;
      break;
    case crf::ConstraintKind::ForbiddenFailureDomainRelation:
      constraint.domain_kind = crf::DomainKind::Rack;
      constraint.domain_relation = crf::DomainRelation::Shared;
      constraint.bound = 0;
      break;
    case crf::ConstraintKind::AdministrativePolicy:
      constraint.policies.push_back(crf::PolicyId::from_value(1100000 + serial));
      break;
    case crf::ConstraintKind::Unset:
    default:
      break;
  }
  return constraint;
}

/// Fills \p out with a constraint mix that covers all 18 kinds and is free of
/// deterministic contradictions.
[[nodiscard]] bool fill_synthetic_set(std::size_t per_set, crf::ConstraintSet& out) {
  if (per_set < kConstraintKindCount || per_set > static_cast<std::size_t>(kLimits.max_constraints_per_set)) {
    return false;
  }
  out = crf::ConstraintSet{};
  out.id = kSyntheticSetId;
  out.generation = kSetGeneration;
  out.state = crf::ConstraintSetState::Active;
  out.name = "bench-synthetic";
  out.declared_tick = 77;
  out.evidence = default_evidence();
  out.constraints.reserve(per_set);

  std::uint64_t serial = 1;
  for (std::size_t slot = 0; slot < kConstraintKindCount; ++slot) {
    out.constraints.push_back(make_synthetic_constraint(slot, serial));
    ++serial;
  }
  std::size_t cursor = 0;
  while (out.constraints.size() < per_set) {
    out.constraints.push_back(
        make_synthetic_constraint(kRepeatableKindSlots[cursor % kRepeatableKindCount], serial));
    ++serial;
    ++cursor;
  }
  return true;
}

/// Canonicalizes and contradiction-checks a fixture outside any timed region.
[[nodiscard]] bool finalize_set(crf::ConstraintSet& set) {
  std::vector<crf::SetDefect> defects;
  std::vector<crf::Contradiction> contradictions;
  const crf::Status status =
      crf::validate_and_finalize_constraint_set(set, kLimits, defects, contradictions);
  return status.ok();
}

/// The 16 mandatory constraints used by the batch-evaluation benchmarks. Every
/// consulted evidence family is bound, and the population is built so that some
/// candidates satisfy all sixteen and some fail exactly one.
[[nodiscard]] bool build_evaluation_set(crf::ConstraintSet& out) {
  out = crf::ConstraintSet{};
  out.id = kEvaluationSetId;
  out.generation = kSetGeneration;
  out.state = crf::ConstraintSetState::Active;
  out.name = "bench-evaluate";
  out.declared_tick = 99;
  out.evidence = default_evidence();
  // Ranking consumes the planner rank and cost so ::crf::order_admissible is
  // measured on its full comparison path.
  out.ranking.consume_planner_rank = true;
  out.ranking.consume_planner_cost = true;
  out.ranking.prefer_lower_cost = true;
  out.ranking.expected_cost_model = crf::PlannerCostModel::HopCountUnits;
  out.ranking.tiebreak = crf::CandidateTiebreak::PathIdAscending;
  out.constraints.reserve(16);

  crf::Constraint required_node = make_mandatory(crf::ConstraintKind::RequiredNode, 1);
  required_node.nodes.push_back(kAnchorNodeA);
  out.constraints.push_back(std::move(required_node));

  crf::Constraint forbidden_node = make_mandatory(crf::ConstraintKind::ForbiddenNode, 2);
  forbidden_node.nodes.push_back(crf::NodeId::from_value(kAbsentNode));
  out.constraints.push_back(std::move(forbidden_node));

  crf::Constraint required_link = make_mandatory(crf::ConstraintKind::RequiredLink, 3);
  required_link.links.push_back(kAnchorLinkA);
  out.constraints.push_back(std::move(required_link));

  crf::Constraint forbidden_link = make_mandatory(crf::ConstraintKind::ForbiddenLink, 4);
  forbidden_link.links.push_back(crf::LinkId::from_value(kAbsentLink));
  out.constraints.push_back(std::move(forbidden_link));

  crf::Constraint required_tier = make_mandatory(crf::ConstraintKind::RequiredTier, 5);
  required_tier.tiers.push_back(kTierA);
  required_tier.tiers.push_back(kTierB);
  out.constraints.push_back(std::move(required_tier));

  crf::Constraint forbidden_tier = make_mandatory(crf::ConstraintKind::ForbiddenTier, 6);
  forbidden_tier.tiers.push_back(crf::TierId::from_value(kAbsentTier));
  out.constraints.push_back(std::move(forbidden_tier));

  crf::Constraint required_site = make_mandatory(crf::ConstraintKind::RequiredSite, 7);
  required_site.sites.push_back(kSiteA);
  required_site.sites.push_back(kSiteB);
  out.constraints.push_back(std::move(required_site));

  crf::Constraint forbidden_site = make_mandatory(crf::ConstraintKind::ForbiddenSite, 8);
  forbidden_site.sites.push_back(crf::SiteId::from_value(kAbsentSite));
  out.constraints.push_back(std::move(forbidden_site));

  crf::Constraint required_capability = make_mandatory(crf::ConstraintKind::RequiredCapability, 9);
  required_capability.capabilities.push_back(kCapability);
  out.constraints.push_back(std::move(required_capability));

  crf::Constraint forbidden_capability =
      make_mandatory(crf::ConstraintKind::ForbiddenCapability, 10);
  forbidden_capability.capabilities.push_back(crf::CapabilityId::from_value(kAbsentCapability));
  // Absence of capability evidence is UNKNOWN, and only an explicit policy lets
  // UNKNOWN satisfy a negative constraint. The candidates carry no evidence at
  // all about this capability, which is exactly that case.
  forbidden_capability.unknown_policy = crf::UnknownPolicy::PermitUnknownNegative;
  out.constraints.push_back(std::move(forbidden_capability));

  crf::Constraint locality_scope = make_mandatory(crf::ConstraintKind::LocalityScope, 11);
  locality_scope.domain_kind = crf::DomainKind::Rack;
  locality_scope.locality_domain = kRackDomain;
  out.constraints.push_back(std::move(locality_scope));

  crf::Constraint isolation_class = make_mandatory(crf::ConstraintKind::IsolationClass, 12);
  isolation_class.isolation_class = kIsolationClass;
  out.constraints.push_back(std::move(isolation_class));

  crf::Constraint domain_relation =
      make_mandatory(crf::ConstraintKind::RequiredFailureDomainRelation, 13);
  domain_relation.domain_kind = crf::DomainKind::FailureDomain;
  domain_relation.domain_relation = crf::DomainRelation::Distinct;
  domain_relation.bound = 2;
  out.constraints.push_back(std::move(domain_relation));

  crf::Constraint administrative_policy =
      make_mandatory(crf::ConstraintKind::AdministrativePolicy, 14);
  administrative_policy.policies.push_back(kPolicy);
  out.constraints.push_back(std::move(administrative_policy));

  crf::Constraint max_latency = make_mandatory(crf::ConstraintKind::MaxLatency, 15);
  max_latency.latency_source = crf::LatencySource::PlannerCost;
  max_latency.bound = 5000;
  out.constraints.push_back(std::move(max_latency));

  crf::Constraint min_bandwidth =
      make_mandatory(crf::ConstraintKind::MinBandwidthCapability, 16);
  min_bandwidth.bound = 1000000;
  out.constraints.push_back(std::move(min_bandwidth));

  return finalize_set(out);
}

// ---------------------------------------------------------------------------
// Candidate fixtures
// ---------------------------------------------------------------------------
constexpr std::size_t kCandidateNodes = 8;
constexpr std::size_t kCandidateLinks = kCandidateNodes - 1;

enum class CandidateFlavor : std::uint8_t {
  Admissible = 0,
  MissingCapability = 1,
  ExcessiveLatency = 2,
};

[[nodiscard]] CandidateFlavor flavor_at(std::size_t index) noexcept {
  switch (index % 3) {
    case 1: return CandidateFlavor::MissingCapability;
    case 2: return CandidateFlavor::ExcessiveLatency;
    default: return CandidateFlavor::Admissible;
  }
}

[[nodiscard]] crf::FailureDomainId failure_domain_at(std::uint64_t seed) noexcept {
  return (seed % 2) == 0 ? kDomainA : kDomainB;
}

/// Builds one candidate. The first and last nodes and links are shared by the
/// whole population so a single constraint set can require them; interior
/// identities are unique per candidate. Evidence vectors are deliberately
/// appended out of canonical order so canonicalization does real sorting work.
void build_candidate(std::uint64_t index, CandidateFlavor flavor, crf::CandidatePath& out) {
  out = crf::CandidatePath{};
  out.path = crf::PathId::from_value(1000 + index);
  out.authority_generation = crf::PathAuthorityGeneration::from_value(kPathAuthorityGenerationValue);
  out.authority_verdict = crf::PathAuthorityVerdict::Legal;
  out.planner_generation = crf::PlannerGeneration::from_value(kPlannerGenerationValue);
  out.has_planner_rank = true;
  out.planner_rank = static_cast<std::uint32_t>(index % 8);
  out.has_planner_cost = true;
  out.planner_cost = static_cast<std::int64_t>(1000 + (index % 13));
  out.cost_model = crf::PlannerCostModel::HopCountUnits;
  out.hop_count = static_cast<std::uint32_t>(kCandidateLinks);

  const std::uint64_t node_space = 100000 + index * 100;
  out.nodes.reserve(kCandidateNodes);
  for (std::size_t position = 0; position < kCandidateNodes; ++position) {
    crf::NodeFact node;
    if (position == 0) {
      node.node = kAnchorNodeA;
    } else if (position + 1 == kCandidateNodes) {
      node.node = kAnchorNodeB;
    } else {
      node.node = crf::NodeId::from_value(node_space + position);
    }
    node.tier = ((position % 2) == 0) ? kTierA : kTierB;
    node.site = ((position % 2) == 0) ? kSiteA : kSiteB;
    node.localities.push_back(crf::LocalityRef{crf::DomainKind::Plane, kPlaneLocality});
    node.localities.push_back(crf::LocalityRef{crf::DomainKind::Rack, kRackDomain});
    node.domains.push_back(crf::FailureDomainRef{crf::DomainKind::FailureDomain,
                                                 failure_domain_at(index + position)});
    node.domains.push_back(
        crf::FailureDomainRef{crf::DomainKind::Plane, kPlaneFailureDomain});
    node.capabilities.push_back(crf::CapabilityRef{
        kSecondaryCapability, crf::CapabilityGeneration::from_value(kCapabilityGenerationValue)});
    node.capabilities.push_back(
        crf::CapabilityRef{kCapability, crf::CapabilityGeneration::from_value(kCapabilityGenerationValue)});
    node.isolation.push_back(crf::IsolationAttestation{
        kSecondaryIsolationClass,
        crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue)});
    node.isolation.push_back(crf::IsolationAttestation{
        kIsolationClass, crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue)});
    if (flavor == CandidateFlavor::MissingCapability && position == 3) {
      node.capabilities.clear();
    }
    out.nodes.push_back(std::move(node));
  }

  const std::uint64_t link_space = 100000 + index * 100;
  out.links.reserve(kCandidateLinks);
  for (std::size_t position = 0; position < kCandidateLinks; ++position) {
    crf::LinkFact link;
    if (position == 0) {
      link.link = kAnchorLinkA;
    } else if (position + 1 == kCandidateLinks) {
      link.link = kAnchorLinkB;
    } else {
      link.link = crf::LinkId::from_value(link_space + 500 + position);
    }
    link.endpoints[0] = out.nodes[position].node;
    link.endpoints[1] = out.nodes[position + 1].node;
    link.bandwidth.model = crf::CapabilityModel::DeclaredCapabilityRegistry;
    link.bandwidth.provenance = crf::EvidenceProvenance::FabricCapabilityRegistry;
    link.bandwidth.bits_per_second = 10000000;
    link.bandwidth.generation = crf::CapabilityGeneration::from_value(kCapabilityGenerationValue);
    link.bandwidth.observed_tick = 500;
    link.domains.push_back(crf::FailureDomainRef{crf::DomainKind::FailureDomain,
                                                 failure_domain_at(index + position + kCandidateNodes)});
    link.domains.push_back(
        crf::FailureDomainRef{crf::DomainKind::Plane, kPlaneFailureDomain});
    link.capabilities.push_back(crf::CapabilityRef{
        kSecondaryCapability, crf::CapabilityGeneration::from_value(kCapabilityGenerationValue)});
    link.capabilities.push_back(
        crf::CapabilityRef{kCapability, crf::CapabilityGeneration::from_value(kCapabilityGenerationValue)});
    link.isolation.push_back(crf::IsolationAttestation{
        kSecondaryIsolationClass,
        crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue)});
    link.isolation.push_back(crf::IsolationAttestation{
        kIsolationClass, crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue)});
    out.links.push_back(std::move(link));
  }

  out.latency.source = crf::LatencySource::PlannerCost;
  out.latency.provenance = crf::EvidenceProvenance::PlannerModel;
  out.latency.micros = flavor == CandidateFlavor::ExcessiveLatency ? 9000 : 1200;
  out.latency.planner_generation = crf::PlannerGeneration::from_value(kPlannerGenerationValue);
  out.policies.push_back(
      crf::PolicyAttestation{kSecondaryPolicy, crf::PolicyGeneration::from_value(kPolicyGenerationValue)});
  out.policies.push_back(
      crf::PolicyAttestation{kPolicy, crf::PolicyGeneration::from_value(kPolicyGenerationValue)});

  out.evidence.topology = crf::TopologyGeneration::from_value(kTopologyGenerationValue);
  out.evidence.link_state = crf::LinkStateGeneration::from_value(kLinkStateGenerationValue);
  out.evidence.capability = crf::CapabilityGeneration::from_value(kCapabilityGenerationValue);
  out.evidence.failure_domain = crf::FailureDomainGeneration::from_value(kFailureDomainGenerationValue);
  out.evidence.policy = crf::PolicyGeneration::from_value(kPolicyGenerationValue);
  out.evidence.planner = crf::PlannerGeneration::from_value(kPlannerGenerationValue);
  out.evidence.path_authority = crf::PathAuthorityGeneration::from_value(kPathAuthorityGenerationValue);
  out.evidence.consulted = kAllFamilies;
  out.evidence.captured_tick = 500;
}

/// Builds and canonicalizes a whole population.
[[nodiscard]] bool build_population(std::size_t count, std::vector<crf::CandidatePath>& out) {
  out.clear();
  out.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    crf::CandidatePath candidate;
    build_candidate(static_cast<std::uint64_t>(index), flavor_at(index), candidate);
    const crf::Status status = crf::canonicalize_candidate(candidate, kLimits);
    if (!status.ok()) {
      return false;
    }
    out.push_back(std::move(candidate));
  }
  return true;
}

/// Mirrors the canonical order ::crf::evaluate_batch derives internally, so the
/// batch records and this population stay parallel arrays.
void canonical_population_order(std::span<const crf::CandidatePath> input,
                                std::vector<crf::CandidatePath>& out) {
  std::vector<crf::CandidatePath> ordered(input.begin(), input.end());
  std::stable_sort(ordered.begin(), ordered.end(), crf::candidate_canonical_less);
  out.clear();
  out.reserve(ordered.size());
  for (const crf::CandidatePath& candidate : ordered) {
    if (!out.empty() && out.back().path == candidate.path) {
      continue;
    }
    out.push_back(candidate);
  }
}

[[nodiscard]] crf::EvaluationContext make_evaluation_context(const crf::ConstraintSet& set) {
  crf::EvaluationContext context;
  context.set = &set;
  context.current = default_evidence();
  context.requested_set_generation = set.generation;
  context.limits = &kLimits;
  context.now_tick = 5000;
  context.provenance.epoch = crf::CoordinatorEpoch::from_value(1);
  context.provenance.publisher = crf::PublisherId::from_value(7);
  context.provenance.worker_boot = crf::WorkerBootId::from_value(9);
  context.provenance.attempt = crf::MutationAttemptId::from_value(11);
  context.provenance.request = crf::RequestId::from_value(13);
  context.generation = crf::EvaluationGeneration::from_value(1);
  context.authority_verified = true;
  return context;
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------
void run_constraint_set_canonicalize() {
  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    const std::size_t per_set = kSetScaleConstraints[scale];
    const std::size_t iterations = kSetScaleIterations[scale];
    std::vector<crf::SetDefect> defects;
    std::vector<crf::Contradiction> contradictions;
    std::uint64_t processed = 0;
    std::string why;
    bool ok = true;

    // Construction is part of the measured pipeline: a coordinator receives a
    // freshly declared set and finalizes it in one pass.
    const Stopwatch watch;
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
      crf::ConstraintSet set;
      if (!fill_synthetic_set(per_set, set)) {
        why = "the synthetic constraint set could not be built";
        ok = false;
        break;
      }
      const crf::Status status =
          crf::validate_and_finalize_constraint_set(set, kLimits, defects, contradictions);
      if (!status.ok()) {
        why = status.detail();
        ok = false;
        break;
      }
      g_sink = g_sink + set.digest.leading_u64();
      processed += set.constraints.size();
    }
    const std::uint64_t nanos = watch.elapsed_nanos();
    if (!ok) {
      report_error("constraint_set_canonicalize", why);
      continue;
    }
    print_throughput("constraint_set_canonicalize", "constraints", processed, nanos);
  }
}

void run_candidate_canonicalize() {
  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    const std::size_t count = kCandidateScaleCounts[scale];
    std::vector<crf::CandidatePath> candidates;
    candidates.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
      crf::CandidatePath candidate;
      build_candidate(static_cast<std::uint64_t>(index), flavor_at(index), candidate);
      candidates.push_back(std::move(candidate));
    }

    // The population is built outside the timed region: this benchmark measures
    // canonicalization of fresh, unsorted candidates.
    std::string why;
    bool ok = true;
    const Stopwatch watch;
    for (crf::CandidatePath& candidate : candidates) {
      const crf::Status status = crf::canonicalize_candidate(candidate, kLimits);
      if (!status.ok()) {
        why = status.detail();
        ok = false;
        break;
      }
      g_sink = g_sink + candidate.hop_count;
    }
    const std::uint64_t nanos = watch.elapsed_nanos();
    if (!ok) {
      report_error("candidate_canonicalize", why);
      continue;
    }
    print_throughput("candidate_canonicalize", "candidates", count, nanos);
  }
}

[[nodiscard]] bool same_ordering(const crf::EvaluationBatch& first,
                                 const crf::EvaluationBatch& second) {
  if (first.admissible_order.size() != second.admissible_order.size()) {
    return false;
  }
  for (std::size_t index = 0; index < first.admissible_order.size(); ++index) {
    if (first.admissible_order[index].path != second.admissible_order[index].path) {
      return false;
    }
    if (first.admissible_order[index].record_index != second.admissible_order[index].record_index) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool same_record_digests(const crf::EvaluationBatch& first,
                                       const crf::EvaluationBatch& second) {
  if (first.records.size() != second.records.size()) {
    return false;
  }
  for (std::size_t index = 0; index < first.records.size(); ++index) {
    if (first.records[index].digest != second.records[index].digest) {
      return false;
    }
    if (first.records[index].id != second.records[index].id) {
      return false;
    }
    if (first.records[index].outcome != second.records[index].outcome) {
      return false;
    }
    if (first.records[index].primary_reason != second.records[index].primary_reason) {
      return false;
    }
  }
  return true;
}

/// Runs the batch benchmark twice over one identical population and reports
/// whether the admissible ordering and every per-record digest agree.
void run_determinism_check(const crf::EvaluationContext& context) {
  constexpr std::size_t kCheckPopulation = 64;
  std::vector<crf::CandidatePath> population;
  if (!build_population(kCheckPopulation, population)) {
    report_error("determinism", "the determinism population could not be canonicalized");
    std::printf("bench_deterministic no\n");
    std::fflush(stdout);
    return;
  }
  const crf::Result<crf::EvaluationBatch> first = crf::evaluate_batch(context, population);
  const crf::Result<crf::EvaluationBatch> second = crf::evaluate_batch(context, population);
  if (!first.ok() || !second.ok()) {
    report_error("determinism", "the determinism batch could not be evaluated");
    std::printf("bench_deterministic no\n");
    std::fflush(stdout);
    return;
  }
  const bool identical = same_ordering(first.value(), second.value()) &&
                         same_record_digests(first.value(), second.value());
  if (!identical) {
    report_error("determinism", "two identical runs produced different evaluation batches");
  }
  std::printf("bench_deterministic %s\n", identical ? "yes" : "no");
  std::fflush(stdout);
}

void run_evaluation_and_ordering() {
  crf::ConstraintSet set;
  if (!build_evaluation_set(set)) {
    report_error("evaluate_batch", "the evaluation constraint set did not finalize");
    return;
  }
  const crf::EvaluationContext context = make_evaluation_context(set);

  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    const std::size_t population_size = kBatchScalePopulations[scale];
    const std::size_t repeats = kBatchScaleRepeats[scale];

    std::vector<crf::CandidatePath> population;
    if (!build_population(population_size, population)) {
      report_error("evaluate_batch", "the candidate population could not be canonicalized");
      continue;
    }
    std::vector<crf::CandidatePath> ordered;
    canonical_population_order(population, ordered);

    std::uint64_t evaluated = 0;
    std::uint64_t admissible = 0;
    crf::EvaluationBatch last;
    std::string why;
    bool ok = true;
    const Stopwatch watch;
    for (std::size_t repeat = 0; repeat < repeats; ++repeat) {
      crf::Result<crf::EvaluationBatch> batch = crf::evaluate_batch(context, population);
      if (!batch.ok()) {
        why = batch.detail();
        ok = false;
        break;
      }
      evaluated += batch.value().records.size();
      admissible += batch.value().admissible_order.size();
      last = std::move(batch.value());
    }
    const std::uint64_t nanos = watch.elapsed_nanos();
    if (!ok) {
      report_error("evaluate_batch", why);
      continue;
    }
    print_throughput("evaluate_batch", "candidate_evaluations", evaluated, nanos);
    print_admissible("evaluate_batch", kScaleNames[scale], evaluated, admissible);

    if (last.records.size() != ordered.size()) {
      report_error("order_admissible", "the batch records do not match the canonical population");
      continue;
    }
    const std::size_t order_repeats = kOrderScaleRepeats[scale];
    std::uint64_t records_ordered = 0;
    const Stopwatch order_watch;
    for (std::size_t repeat = 0; repeat < order_repeats; ++repeat) {
      const std::vector<crf::RankedCandidate> order =
          crf::order_admissible(last.records, ordered, set.ranking);
      records_ordered += last.records.size();
      g_sink = g_sink + order.size();
    }
    print_throughput("order_admissible", "records", records_ordered, order_watch.elapsed_nanos());
  }

  run_determinism_check(context);
}

void run_digest() {
  std::vector<crf::ConstraintSet> sets;
  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    crf::ConstraintSet set;
    if (!fill_synthetic_set(kSetScaleConstraints[scale], set) || !finalize_set(set)) {
      report_error("digest", "the digest constraint set could not be finalized");
      return;
    }
    sets.push_back(std::move(set));
  }

  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    const std::size_t count = kDigestScaleCandidates[scale];
    std::vector<crf::CandidatePath> candidates;
    if (!build_population(count, candidates)) {
      report_error("digest", "the digest population could not be canonicalized");
      continue;
    }
    const Stopwatch candidate_watch;
    for (const crf::CandidatePath& candidate : candidates) {
      g_sink = g_sink + crf::candidate_digest(candidate).leading_u64();
    }
    print_throughput("digest", "candidate_digests", count, candidate_watch.elapsed_nanos());

    // The set digest is measured against the set of this scale, so the three
    // reported figures trace the cost of a growing definition.
    const Stopwatch set_watch;
    for (std::size_t repeat = 0; repeat < kDigestScaleSetRepeats; ++repeat) {
      g_sink = g_sink + crf::constraint_set_digest(sets[scale]).leading_u64();
    }
    print_throughput("digest", "constraint_set_digests", kDigestScaleSetRepeats,
                     set_watch.elapsed_nanos());
  }
}

/// Builds the durable fixture for one scale: two canonical sets, the candidate
/// populations they were evaluated against, real evaluation records, fenced
/// boots, mutation attempts and watermarks.
[[nodiscard]] bool build_persistent_state(std::size_t scale, crf::PersistentState& out,
                                          std::string& why) {
  const std::size_t per_set = kSetScaleConstraints[scale];
  const std::size_t evaluation_count = kPersistedEvaluationCounts[scale];

  crf::ConstraintSet definition;
  if (!fill_synthetic_set(per_set, definition) || !finalize_set(definition)) {
    why = "the persisted constraint set could not be finalized";
    return false;
  }
  crf::ConstraintSet evaluation_set;
  if (!build_evaluation_set(evaluation_set) || !finalize_set(evaluation_set)) {
    why = "the persisted evaluation set could not be finalized";
    return false;
  }

  std::vector<crf::CandidatePath> population;
  if (!build_population(kLimits.max_candidates_per_evaluation, population)) {
    why = "the persisted candidate population could not be canonicalized";
    return false;
  }

  const crf::EvaluationContext context = make_evaluation_context(evaluation_set);
  const std::vector<crf::CandidatePath> evaluated_slice(
      population.begin(), population.begin() + static_cast<std::ptrdiff_t>(evaluation_count));
  const crf::Result<crf::EvaluationBatch> batch = crf::evaluate_batch(context, evaluated_slice);
  if (!batch.ok()) {
    why = "the persisted evaluation batch could not be evaluated";
    return false;
  }

  out = crf::PersistentState{};
  out.epoch = crf::CoordinatorEpoch::from_value(3);
  out.initialized = true;
  out.evidence = default_evidence();
  out.last_evaluation_generation = crf::EvaluationGeneration::from_value(1);
  out.sets.push_back(definition);
  out.sets.push_back(evaluation_set);
  out.evaluations = batch.value().records;

  crf::CandidatePopulation definition_population;
  definition_population.set_id = definition.id;
  definition_population.candidates = population;
  out.populations.push_back(std::move(definition_population));
  crf::CandidatePopulation evaluation_population;
  evaluation_population.set_id = evaluation_set.id;
  evaluation_population.candidates = population;
  out.populations.push_back(std::move(evaluation_population));

  crf::FencedBootRecord first_boot;
  first_boot.boot = crf::WorkerBootId::from_value(51);
  first_boot.fenced_at = crf::CoordinatorEpoch::from_value(2);
  first_boot.fenced_tick = 10;
  out.fenced_boots.push_back(first_boot);
  crf::FencedBootRecord second_boot;
  second_boot.boot = crf::WorkerBootId::from_value(52);
  second_boot.fenced_at = crf::CoordinatorEpoch::from_value(3);
  second_boot.fenced_tick = 20;
  out.fenced_boots.push_back(second_boot);

  crf::MutationAttemptRecord first_attempt;
  first_attempt.attempt = crf::MutationAttemptId::from_value(61);
  first_attempt.payload = crf::candidate_digest(population.front());
  first_attempt.recorded_tick = 30;
  out.attempts.push_back(first_attempt);
  crf::MutationAttemptRecord second_attempt;
  second_attempt.attempt = crf::MutationAttemptId::from_value(62);
  second_attempt.payload = crf::persistent_state_digest(out);
  second_attempt.recorded_tick = 40;
  out.attempts.push_back(second_attempt);

  if (!out.watermarks.advance_family(crf::EvidenceFamily::Topology, kTopologyGenerationValue) ||
      !out.watermarks.advance_family(crf::EvidenceFamily::Capability, kCapabilityGenerationValue)) {
    why = "the watermark fixture could not be advanced";
    return false;
  }
  const crf::InvalidationKey set_key{crf::InvalidationKeyKind::ConstraintSet,
                                     definition.id.value()};
  if (!out.watermarks.advance_key(set_key, kSetGeneration.value())) {
    why = "the watermark fixture could not be advanced";
    return false;
  }

  const crf::Status valid = crf::validate_persistent_state(out, kLimits);
  if (!valid.ok()) {
    why = "the persisted fixture is invalid: " + valid.detail();
    return false;
  }
  return true;
}

void run_persistence() {
  std::error_code error;
  const std::filesystem::path temp_root = std::filesystem::temp_directory_path(error);
  if (error) {
    report_error("persistence_round_trip", "no temporary directory is available");
    return;
  }
  const std::filesystem::path directory = temp_root / "crf_bench_persistence";
  static_cast<void>(std::filesystem::remove_all(directory, error));
  error.clear();
  static_cast<void>(std::filesystem::create_directories(directory, error));
  if (error) {
    report_error("persistence_round_trip", "the temporary benchmark directory could not be created");
    return;
  }

  std::uint64_t durable_trips = 0;
  std::uint64_t durable_nanos = 0;

  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    crf::PersistentState state;
    std::string why;
    if (!build_persistent_state(scale, state, why)) {
      report_error("persistence_round_trip", why);
      continue;
    }

    crf::ByteWriter writer;
    crf::encode_persistent_state(writer, state);
    const std::uint64_t payload_bytes = writer.size();
    const std::vector<std::byte> envelope = crf::encode_envelope(writer.span());
    print_bytes("persistence_round_trip", kScaleNames[scale],
                static_cast<std::uint64_t>(envelope.size()));

    const std::size_t repeats = kPersistenceScaleRepeats[scale];
    std::uint64_t completed = 0;
    std::string failure;
    const Stopwatch watch;
    for (std::size_t repeat = 0; repeat < repeats; ++repeat) {
      crf::ByteWriter encoding;
      crf::encode_persistent_state(encoding, state);
      const std::vector<std::byte> raw = crf::encode_envelope(encoding.span());
      std::vector<std::byte> payload;
      const crf::Status decoded = crf::decode_envelope(raw, kLimits, payload);
      if (!decoded.ok()) {
        failure = decoded.detail();
        break;
      }
      crf::ByteReader reader(payload);
      crf::PersistentState restored;
      if (!crf::decode_persistent_state(reader, kLimits, restored)) {
        failure = "the persisted state payload could not be decoded";
        break;
      }
      g_sink = g_sink + restored.sets.size() + restored.evaluations.size() +
               restored.populations.size();
      ++completed;
    }
    const std::uint64_t nanos = watch.elapsed_nanos();
    if (completed == repeats) {
      print_throughput("persistence_round_trip", "bytes", payload_bytes * repeats, nanos);
    } else {
      report_error("persistence_round_trip", failure);
    }

    const std::filesystem::path store_file = directory / ("state_" + std::string(kScaleNames[scale]) + ".crf");
    const crf::Result<std::unique_ptr<crf::DurableStore>> store =
        crf::DurableStore::open(store_file.string(), kLimits, true);
    if (!store.ok()) {
      report_error("persistence_durable_store", store.detail());
      continue;
    }
    const crf::Digest256 expected = crf::persistent_state_digest(state);
    const std::size_t durable_repeats = kDurableScaleRepeats[scale];
    std::uint64_t trips = 0;
    const Stopwatch durable_watch;
    for (std::size_t repeat = 0; repeat < durable_repeats; ++repeat) {
      const crf::Status saved = store.value()->save(state);
      if (!saved.ok()) {
        failure = saved.detail();
        break;
      }
      const crf::Result<crf::PersistentState> loaded = store.value()->load();
      if (!loaded.ok()) {
        failure = loaded.detail();
        break;
      }
      if (crf::persistent_state_digest(loaded.value()) != expected) {
        failure = "the durable round trip changed the persisted state";
        break;
      }
      ++trips;
    }
    durable_nanos += durable_watch.elapsed_nanos();
    durable_trips += trips;
    if (trips != durable_repeats) {
      report_error("persistence_durable_store", failure);
    }
  }

  if (durable_trips != 0) {
    print_throughput("persistence_durable_store", "round_trips", durable_trips, durable_nanos);
  }
  static_cast<void>(std::filesystem::remove_all(directory, error));
}

void run_contradiction_scan() {
  for (std::size_t scale = 0; scale < kScaleCount; ++scale) {
    crf::ConstraintSet set;
    if (!fill_synthetic_set(kSetScaleConstraints[scale], set) || !finalize_set(set)) {
      report_error("contradiction_scan", "the contradiction fixture could not be finalized");
      continue;
    }
    const std::size_t repeats = kContradictionScaleRepeats[scale];
    std::vector<crf::Contradiction> contradictions;
    std::uint64_t scans = 0;
    std::string why;
    const Stopwatch watch;
    for (std::size_t repeat = 0; repeat < repeats; ++repeat) {
      const crf::Status status = crf::detect_contradictions(set, kLimits, contradictions);
      if (!status.ok()) {
        why = status.detail();
        break;
      }
      ++scans;
    }
    const std::uint64_t nanos = watch.elapsed_nanos();
    if (scans != repeats) {
      report_error("contradiction_scan", why);
      continue;
    }
    print_throughput("contradiction_scan", "constraint_set_scans", scans, nanos);
  }
}

}  // namespace

int main() {
  const Stopwatch total;
  run_constraint_set_canonicalize();
  run_candidate_canonicalize();
  run_evaluation_and_ordering();
  run_digest();
  run_persistence();
  run_contradiction_scan();

  const std::uint64_t nanos = total.elapsed_nanos();
  std::printf("bench_total %llu.%03llu\n",
              static_cast<unsigned long long>(nanos_to_millis(nanos)),
              static_cast<unsigned long long>(nanos_to_millis_fraction(nanos)));
  std::fflush(stdout);
  return g_failed ? 1 : 0;
}
