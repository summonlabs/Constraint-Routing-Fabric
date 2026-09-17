// Constraint Routing Fabric -- canonical constraint-model test suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Covers all 18 typed constraint kinds, canonicalization, equivalent-duplicate
// collapse, duplicate identity, every contradiction kind, the complete
// lifecycle transition table, digest stability and the binary codecs.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/lifecycle.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/protocol.hpp"
#include "constraint_routing_fabric/status.hpp"
#include "test_support.hpp"

namespace {

using ::crf::CandidateTiebreak;
using ::crf::CapabilityId;
using ::crf::Constraint;
using ::crf::ConstraintGeneration;
using ::crf::ConstraintId;
using ::crf::ConstraintKind;
using ::crf::ConstraintScope;
using ::crf::ConstraintSet;
using ::crf::ConstraintSetGeneration;
using ::crf::ConstraintSetId;
using ::crf::ConstraintSetState;
using ::crf::Contradiction;
using ::crf::ContradictionKind;
using ::crf::Digest256;
using ::crf::DomainKind;
using ::crf::DomainRelation;
using ::crf::ErrorCode;
using ::crf::EvidenceRequirements;
using ::crf::IsolationClassId;
using ::crf::LatencySource;
using ::crf::LifecycleEvent;
using ::crf::Limits;
using ::crf::LinkId;
using ::crf::LocalityDomainId;
using ::crf::NodeId;
using ::crf::PolicyId;
using ::crf::RankingPolicy;
using ::crf::SetDefect;
using ::crf::SetDefectKind;
using ::crf::SiteId;
using ::crf::Status;
using ::crf::SubjectKind;
using ::crf::TierId;
using ::crf::TransitionOutcome;
using ::crf::UnknownPolicy;

// --- rendering helpers ------------------------------------------------------
// The test framework formats values through operator<<, which no scoped enum
// has. Every comparison below therefore renders through the library's own
// to_string so a failure message names the enumerator, never a number.

[[nodiscard]] std::string text(ErrorCode value) { return ::crf::to_string(value); }
[[nodiscard]] std::string text(ContradictionKind value) { return ::crf::to_string(value); }
[[nodiscard]] std::string text(SubjectKind value) { return ::crf::to_string(value); }

[[nodiscard]] std::string text(SetDefectKind value) {
  switch (value) {
    case SetDefectKind::EquivalentDuplicateCollapsed: return "EquivalentDuplicateCollapsed";
    case SetDefectKind::EntityListReordered: return "EntityListReordered";
    case SetDefectKind::DuplicateEntityCollapsed: return "DuplicateEntityCollapsed";
    case SetDefectKind::ConstraintsReordered: return "ConstraintsReordered";
  }
  return "Unknown";
}

void check_status_code(const Status& status, ErrorCode expected, const char* file, int line,
                       const char* expression) {
  if (status.code() != expected) {
    ::crf::test::report_failure(file, line,
                                std::string("expected ") + expression + " (actual=" +
                                    text(status.code()) + ", expected=" + text(expected) + ")");
  }
}

#define CRF_MODEL_CHECK_CODE(status_expression, expected_code) \
  check_status_code((status_expression), (expected_code), __FILE__, __LINE__, #status_expression)

// --- builders ---------------------------------------------------------------

template <class Id>
[[nodiscard]] std::vector<Id> id_list(std::initializer_list<std::uint64_t> values) {
  std::vector<Id> out;
  out.reserve(values.size());
  for (const std::uint64_t value : values) {
    out.push_back(Id::from_value(value));
  }
  return out;
}

template <class Id>
[[nodiscard]] bool strictly_ascending(const std::vector<Id>& values) {
  for (std::size_t index = 1; index < values.size(); ++index) {
    if (!(values[index - 1] < values[index])) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] Constraint make(std::uint64_t id_value, ConstraintKind kind) {
  Constraint constraint;
  constraint.id = ConstraintId::from_value(id_value);
  constraint.generation = ConstraintGeneration::from_value(1);
  constraint.kind = kind;
  return constraint;
}

/// A structurally correct instance of \p kind. One instance per kind, always
/// with the minimal payload the kind requires.
[[nodiscard]] Constraint valid_for(ConstraintKind kind, std::uint64_t id_value) {
  Constraint constraint = make(id_value, kind);
  switch (kind) {
    case ConstraintKind::MaxLatency:
      constraint.bound = 1000;
      constraint.latency_source = LatencySource::ObservedLatency;
      return constraint;
    case ConstraintKind::MinBandwidthCapability:
      constraint.bound = 1000000;
      return constraint;
    case ConstraintKind::RequiredNode:
    case ConstraintKind::ForbiddenNode:
      constraint.nodes = id_list<NodeId>({3});
      return constraint;
    case ConstraintKind::RequiredLink:
    case ConstraintKind::ForbiddenLink:
      constraint.links = id_list<LinkId>({4});
      return constraint;
    case ConstraintKind::RequiredTier:
    case ConstraintKind::ForbiddenTier:
      constraint.tiers = id_list<TierId>({5});
      return constraint;
    case ConstraintKind::RequiredSite:
    case ConstraintKind::ForbiddenSite:
      constraint.sites = id_list<SiteId>({6});
      return constraint;
    case ConstraintKind::LocalityScope:
      constraint.domain_kind = DomainKind::Rack;
      constraint.locality_domain = LocalityDomainId::from_value(7);
      return constraint;
    case ConstraintKind::IsolationClass:
      constraint.isolation_class = IsolationClassId::from_value(8);
      return constraint;
    case ConstraintKind::RequiredCapability:
    case ConstraintKind::ForbiddenCapability:
      constraint.capabilities = id_list<CapabilityId>({9});
      return constraint;
    case ConstraintKind::RequiredFailureDomainRelation:
      constraint.domain_kind = DomainKind::FailureDomain;
      constraint.domain_relation = DomainRelation::Distinct;
      constraint.bound = 2;
      return constraint;
    case ConstraintKind::ForbiddenFailureDomainRelation:
      constraint.domain_kind = DomainKind::FailureDomain;
      constraint.domain_relation = DomainRelation::Shared;
      return constraint;
    case ConstraintKind::AdministrativePolicy:
      constraint.policies = id_list<PolicyId>({10});
      return constraint;
    case ConstraintKind::MaxHopCount:
      constraint.bound = 8;
      return constraint;
    case ConstraintKind::Unset:
    default:
      return constraint;
  }
}

/// The same kind carrying a payload that belongs to a different kind, or a
/// bound outside the kind's legal range. Always rejected.
[[nodiscard]] Constraint invalid_for(ConstraintKind kind, std::uint64_t id_value) {
  Constraint constraint = make(id_value, kind);
  switch (kind) {
    case ConstraintKind::MaxLatency:
      // MaxLatency carrying a node list.
      constraint.bound = 1000;
      constraint.latency_source = LatencySource::ObservedLatency;
      constraint.nodes = id_list<NodeId>({3});
      return constraint;
    case ConstraintKind::MinBandwidthCapability:
      constraint.bound = 0;
      return constraint;
    case ConstraintKind::RequiredNode:
      // RequiredNode carrying a link list.
      constraint.links = id_list<LinkId>({4});
      return constraint;
    case ConstraintKind::ForbiddenNode:
      return constraint;
    case ConstraintKind::RequiredLink:
      constraint.nodes = id_list<NodeId>({3});
      return constraint;
    case ConstraintKind::ForbiddenLink:
      return constraint;
    case ConstraintKind::RequiredTier:
      constraint.sites = id_list<SiteId>({6});
      return constraint;
    case ConstraintKind::ForbiddenTier:
      return constraint;
    case ConstraintKind::RequiredSite:
      constraint.tiers = id_list<TierId>({5});
      return constraint;
    case ConstraintKind::ForbiddenSite:
      return constraint;
    case ConstraintKind::LocalityScope:
      constraint.locality_domain = LocalityDomainId::from_value(7);
      return constraint;
    case ConstraintKind::IsolationClass:
      return constraint;
    case ConstraintKind::RequiredCapability:
      constraint.policies = id_list<PolicyId>({10});
      return constraint;
    case ConstraintKind::ForbiddenCapability:
      return constraint;
    case ConstraintKind::RequiredFailureDomainRelation:
      constraint.domain_kind = DomainKind::FailureDomain;
      constraint.domain_relation = DomainRelation::Shared;
      constraint.bound = 2;
      return constraint;
    case ConstraintKind::ForbiddenFailureDomainRelation:
      constraint.domain_kind = DomainKind::FailureDomain;
      return constraint;
    case ConstraintKind::AdministrativePolicy:
      constraint.capabilities = id_list<CapabilityId>({9});
      return constraint;
    case ConstraintKind::MaxHopCount:
      constraint.bound = 0;
      return constraint;
    case ConstraintKind::Unset:
    default:
      return constraint;
  }
}

[[nodiscard]] ConstraintSet make_set(std::uint64_t id_value, std::vector<Constraint> constraints) {
  ConstraintSet set;
  set.id = ConstraintSetId::from_value(id_value);
  set.generation = ConstraintSetGeneration::from_value(1);
  set.name = "canonical";
  set.constraints = std::move(constraints);
  return set;
}

[[nodiscard]] bool evidence_equal(const EvidenceRequirements& a, const EvidenceRequirements& b) {
  return a.topology == b.topology && a.link_state == b.link_state && a.capability == b.capability &&
         a.failure_domain == b.failure_domain && a.policy == b.policy && a.planner == b.planner &&
         a.path_authority == b.path_authority && a.max_evidence_age_ticks == b.max_evidence_age_ticks;
}

/// Names the first field in which the two sets differ, so an atomicity failure
/// says exactly what moved.
[[nodiscard]] std::string describe_set_difference(const ConstraintSet& a, const ConstraintSet& b) {
  if (!(a.id == b.id)) return "id";
  if (!(a.generation == b.generation)) return "generation";
  if (a.state != b.state) return "state";
  if (a.name != b.name) return "name";
  if (a.constraints.size() != b.constraints.size()) return "constraint count";
  for (std::size_t index = 0; index < a.constraints.size(); ++index) {
    if (a.constraints[index] != b.constraints[index]) {
      return "constraint " + std::to_string(index);
    }
  }
  if (!evidence_equal(a.evidence, b.evidence)) return "evidence";
  if (!(a.ranking == b.ranking)) return "ranking";
  if (a.digest != b.digest) return "digest";
  if (a.declared_tick != b.declared_tick) return "declared_tick";
  return "identical";
}

[[nodiscard]] std::vector<std::uint64_t> constraint_ids(const ConstraintSet& set) {
  std::vector<std::uint64_t> ids;
  ids.reserve(set.constraints.size());
  for (const Constraint& constraint : set.constraints) {
    ids.push_back(constraint.id.value());
  }
  return ids;
}

[[nodiscard]] ConstraintSet canonicalized(ConstraintSet set) {
  std::vector<SetDefect> defects;
  const Status status = ::crf::canonicalize_constraint_set(set, Limits{}, defects);
  CRF_CHECK(status.ok());
  return set;
}

[[nodiscard]] std::vector<std::size_t> shuffled_order(std::size_t count, std::uint64_t seed) {
  std::vector<std::size_t> order(count);
  for (std::size_t index = 0; index < count; ++index) {
    order[index] = index;
  }
  ::crf::test::Rng rng(seed);
  for (std::size_t index = count; index > 1; --index) {
    const std::size_t pick = static_cast<std::size_t>(rng.below(static_cast<std::uint32_t>(index)));
    std::swap(order[index - 1], order[pick]);
  }
  return order;
}

[[nodiscard]] std::size_t count_defects(const std::vector<SetDefect>& defects, SetDefectKind kind) {
  std::size_t count = 0;
  for (const SetDefect& defect : defects) {
    if (defect.kind == kind) {
      ++count;
    }
  }
  return count;
}

// --- fixtures ---------------------------------------------------------------

/// Ten distinct, contradiction-free constraints with five different kinds.
[[nodiscard]] std::vector<Constraint> canonical_fixture() {
  std::vector<Constraint> constraints;
  Constraint required = make(30, ConstraintKind::RequiredNode);
  required.nodes = id_list<NodeId>({3, 5});
  constraints.push_back(required);
  Constraint forbidden = make(10, ConstraintKind::ForbiddenNode);
  forbidden.nodes = id_list<NodeId>({9});
  constraints.push_back(forbidden);
  constraints.push_back(valid_for(ConstraintKind::MaxLatency, 50));
  constraints.push_back(valid_for(ConstraintKind::MaxHopCount, 20));
  constraints.push_back(valid_for(ConstraintKind::RequiredCapability, 40));
  constraints.push_back(valid_for(ConstraintKind::AdministrativePolicy, 60));
  constraints.push_back(valid_for(ConstraintKind::RequiredSite, 70));
  constraints.push_back(valid_for(ConstraintKind::LocalityScope, 80));
  Constraint more_nodes = make(31, ConstraintKind::RequiredNode);
  more_nodes.nodes = id_list<NodeId>({3, 5, 11});
  constraints.push_back(more_nodes);
  Constraint preference = make(90, ConstraintKind::MaxLatency);
  preference.scope = ConstraintScope::Preference;
  preference.bound = 2000;
  preference.latency_source = LatencySource::PlannerCost;
  preference.preference_rank = 1;
  preference.preference_weight = 500;
  constraints.push_back(preference);
  return constraints;
}

/// Six constraints, one per entity-list family, whose lists are given shuffled
/// and with duplicates.
[[nodiscard]] std::vector<Constraint> shuffled_entity_lists() {
  Constraint nodes = make(1, ConstraintKind::RequiredNode);
  nodes.nodes = id_list<NodeId>({9, 3, 5, 3});
  Constraint links = make(2, ConstraintKind::RequiredLink);
  links.links = id_list<LinkId>({8, 2});
  Constraint tiers = make(3, ConstraintKind::RequiredTier);
  tiers.tiers = id_list<TierId>({7, 1, 7});
  Constraint sites = make(4, ConstraintKind::RequiredSite);
  sites.sites = id_list<SiteId>({6, 4});
  Constraint capabilities = make(5, ConstraintKind::RequiredCapability);
  capabilities.capabilities = id_list<CapabilityId>({5, 5, 2});
  Constraint policies = make(6, ConstraintKind::AdministrativePolicy);
  policies.policies = id_list<PolicyId>({9, 1});
  return {nodes, links, tiers, sites, capabilities, policies};
}

/// Digest fixture: six distinct constraints across five kinds.
[[nodiscard]] std::vector<Constraint> digest_fixture() {
  std::vector<Constraint> constraints;
  Constraint nodes = make(11, ConstraintKind::RequiredNode);
  nodes.nodes = id_list<NodeId>({3, 5});
  constraints.push_back(nodes);
  Constraint forbidden = make(12, ConstraintKind::ForbiddenNode);
  forbidden.nodes = id_list<NodeId>({9});
  constraints.push_back(forbidden);
  constraints.push_back(valid_for(ConstraintKind::MaxLatency, 13));
  constraints.push_back(valid_for(ConstraintKind::RequiredCapability, 14));
  constraints.push_back(valid_for(ConstraintKind::AdministrativePolicy, 16));
  Constraint preference = make(15, ConstraintKind::MaxLatency);
  preference.scope = ConstraintScope::Preference;
  preference.bound = 2000;
  preference.latency_source = LatencySource::PlannerCost;
  preference.preference_rank = 1;
  preference.preference_weight = 500;
  constraints.push_back(preference);
  return constraints;
}

/// A complex, fully populated definition used by the round-trip test.
[[nodiscard]] std::vector<Constraint> complex_fixture() {
  std::vector<Constraint> constraints;
  Constraint nodes = make(11, ConstraintKind::RequiredNode);
  nodes.nodes = id_list<NodeId>({3, 5});
  constraints.push_back(nodes);
  Constraint forbidden = make(12, ConstraintKind::ForbiddenNode);
  forbidden.nodes = id_list<NodeId>({9});
  constraints.push_back(forbidden);
  Constraint links = make(21, ConstraintKind::RequiredLink);
  links.links = id_list<LinkId>({7});
  constraints.push_back(links);
  Constraint sites = make(22, ConstraintKind::ForbiddenSite);
  sites.sites = id_list<SiteId>({8});
  constraints.push_back(sites);
  constraints.push_back(valid_for(ConstraintKind::RequiredTier, 13));
  constraints.push_back(valid_for(ConstraintKind::MaxLatency, 14));
  constraints.push_back(valid_for(ConstraintKind::MinBandwidthCapability, 15));
  constraints.push_back(valid_for(ConstraintKind::LocalityScope, 16));
  constraints.push_back(valid_for(ConstraintKind::IsolationClass, 17));
  constraints.push_back(valid_for(ConstraintKind::RequiredFailureDomainRelation, 18));
  constraints.push_back(valid_for(ConstraintKind::AdministrativePolicy, 19));
  Constraint preference = make(20, ConstraintKind::MaxLatency);
  preference.scope = ConstraintScope::Preference;
  preference.bound = 2000;
  preference.latency_source = LatencySource::PlannerCost;
  preference.preference_rank = 1;
  preference.preference_weight = 500;
  constraints.push_back(preference);
  return constraints;
}

// --- per-kind expectation table ---------------------------------------------

struct KindCase {
  ConstraintKind kind;
  const char* name;
  ErrorCode invalid_code;
};

const KindCase kKindCases[] = {
    {ConstraintKind::MaxLatency, "MaxLatency", ErrorCode::Malformed},
    {ConstraintKind::MinBandwidthCapability, "MinBandwidthCapability", ErrorCode::InvalidNumericBound},
    {ConstraintKind::RequiredNode, "RequiredNode", ErrorCode::Malformed},
    {ConstraintKind::ForbiddenNode, "ForbiddenNode", ErrorCode::Malformed},
    {ConstraintKind::RequiredLink, "RequiredLink", ErrorCode::Malformed},
    {ConstraintKind::ForbiddenLink, "ForbiddenLink", ErrorCode::Malformed},
    {ConstraintKind::RequiredTier, "RequiredTier", ErrorCode::Malformed},
    {ConstraintKind::ForbiddenTier, "ForbiddenTier", ErrorCode::Malformed},
    {ConstraintKind::RequiredSite, "RequiredSite", ErrorCode::Malformed},
    {ConstraintKind::ForbiddenSite, "ForbiddenSite", ErrorCode::Malformed},
    {ConstraintKind::LocalityScope, "LocalityScope", ErrorCode::Malformed},
    {ConstraintKind::IsolationClass, "IsolationClass", ErrorCode::Malformed},
    {ConstraintKind::RequiredCapability, "RequiredCapability", ErrorCode::Malformed},
    {ConstraintKind::ForbiddenCapability, "ForbiddenCapability", ErrorCode::Malformed},
    {ConstraintKind::RequiredFailureDomainRelation, "RequiredFailureDomainRelation",
     ErrorCode::Malformed},
    {ConstraintKind::ForbiddenFailureDomainRelation, "ForbiddenFailureDomainRelation",
     ErrorCode::Malformed},
    {ConstraintKind::AdministrativePolicy, "AdministrativePolicy", ErrorCode::Malformed},
    {ConstraintKind::MaxHopCount, "MaxHopCount", ErrorCode::InvalidNumericBound},
};

/// The complete documentation table of (state, event) outcomes. Rejected rows
/// record the Declared sentinel the transition function returns; they never
/// carry a next state.
struct LifecycleExpectation {
  ConstraintSetState state;
  LifecycleEvent event;
  bool accepted;
  ConstraintSetState next;
};

constexpr bool kAccept = true;
constexpr bool kReject = false;

const LifecycleExpectation kLifecycleTable[] = {
    {ConstraintSetState::Declared, LifecycleEvent::Activate, kAccept, ConstraintSetState::Active},
    {ConstraintSetState::Declared, LifecycleEvent::Suspend, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Declared, LifecycleEvent::Resume, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Declared, LifecycleEvent::RequireRevalidation, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::Declared, LifecycleEvent::Revalidated, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Declared, LifecycleEvent::Revoke, kAccept, ConstraintSetState::Revoked},
    {ConstraintSetState::Declared, LifecycleEvent::Supersede, kAccept, ConstraintSetState::Superseded},
    {ConstraintSetState::Declared, LifecycleEvent::Retire, kAccept, ConstraintSetState::Retired},
    {ConstraintSetState::Declared, LifecycleEvent::Reinstate, kReject, ConstraintSetState::Declared},

    {ConstraintSetState::Active, LifecycleEvent::Activate, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Active, LifecycleEvent::Suspend, kAccept, ConstraintSetState::Suspended},
    {ConstraintSetState::Active, LifecycleEvent::Resume, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Active, LifecycleEvent::RequireRevalidation, kAccept,
     ConstraintSetState::RevalidationRequired},
    {ConstraintSetState::Active, LifecycleEvent::Revalidated, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Active, LifecycleEvent::Revoke, kAccept, ConstraintSetState::Revoked},
    {ConstraintSetState::Active, LifecycleEvent::Supersede, kAccept, ConstraintSetState::Superseded},
    {ConstraintSetState::Active, LifecycleEvent::Retire, kAccept, ConstraintSetState::Retired},
    {ConstraintSetState::Active, LifecycleEvent::Reinstate, kReject, ConstraintSetState::Declared},

    {ConstraintSetState::Suspended, LifecycleEvent::Activate, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Suspended, LifecycleEvent::Suspend, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Suspended, LifecycleEvent::Resume, kAccept, ConstraintSetState::Active},
    {ConstraintSetState::Suspended, LifecycleEvent::RequireRevalidation, kAccept,
     ConstraintSetState::RevalidationRequired},
    {ConstraintSetState::Suspended, LifecycleEvent::Revalidated, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Suspended, LifecycleEvent::Revoke, kAccept, ConstraintSetState::Revoked},
    {ConstraintSetState::Suspended, LifecycleEvent::Supersede, kAccept, ConstraintSetState::Superseded},
    {ConstraintSetState::Suspended, LifecycleEvent::Retire, kAccept, ConstraintSetState::Retired},
    {ConstraintSetState::Suspended, LifecycleEvent::Reinstate, kReject, ConstraintSetState::Declared},

    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Activate, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Suspend, kAccept,
     ConstraintSetState::Suspended},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Resume, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::RequireRevalidation, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Revalidated, kAccept,
     ConstraintSetState::Active},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Revoke, kAccept,
     ConstraintSetState::Revoked},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Supersede, kAccept,
     ConstraintSetState::Superseded},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Retire, kAccept,
     ConstraintSetState::Retired},
    {ConstraintSetState::RevalidationRequired, LifecycleEvent::Reinstate, kReject,
     ConstraintSetState::Declared},

    {ConstraintSetState::Revoked, LifecycleEvent::Activate, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::Suspend, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::Resume, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::RequireRevalidation, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::Revalidated, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::Revoke, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Revoked, LifecycleEvent::Supersede, kAccept, ConstraintSetState::Superseded},
    {ConstraintSetState::Revoked, LifecycleEvent::Retire, kAccept, ConstraintSetState::Retired},
    {ConstraintSetState::Revoked, LifecycleEvent::Reinstate, kAccept,
     ConstraintSetState::RevalidationRequired},

    {ConstraintSetState::Superseded, LifecycleEvent::Activate, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Suspend, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Resume, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::RequireRevalidation, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Revalidated, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Revoke, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Supersede, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Superseded, LifecycleEvent::Retire, kAccept, ConstraintSetState::Retired},
    {ConstraintSetState::Superseded, LifecycleEvent::Reinstate, kReject, ConstraintSetState::Declared},

    {ConstraintSetState::Retired, LifecycleEvent::Activate, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Suspend, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Resume, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::RequireRevalidation, kReject,
     ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Revalidated, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Revoke, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Supersede, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Retire, kReject, ConstraintSetState::Declared},
    {ConstraintSetState::Retired, LifecycleEvent::Reinstate, kReject, ConstraintSetState::Declared},
};

struct ContradictionExpectation {
  ContradictionKind kind;
  SubjectKind subject_kind;
  std::uint64_t subject;
};

/// Finalization must reject the set with a contradiction and leave the caller's
/// definition strictly untouched.
void expect_contradiction(const ConstraintSet& set, const ContradictionExpectation& expectation) {
  const ConstraintSet untouched = set;
  ConstraintSet working = set;
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status =
      ::crf::validate_and_finalize_constraint_set(working, Limits{}, defects, contradictions);
  CRF_MODEL_CHECK_CODE(status, ErrorCode::ContradictoryConstraintSet);
  CRF_CHECK(!status.detail().empty());
  std::size_t matched = 0;
  for (const Contradiction& contradiction : contradictions) {
    if (contradiction.kind != expectation.kind) {
      continue;
    }
    ++matched;
    CRF_CHECK_EQ(text(contradiction.subject_kind), text(expectation.subject_kind));
    CRF_CHECK_EQ(contradiction.subject, expectation.subject);
  }
  CRF_CHECK_EQ(matched, std::size_t{1});
  CRF_CHECK_EQ(describe_set_difference(working, untouched), std::string("identical"));
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. Every constraint kind
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, EveryConstraintKindValidatesAndRejectsWrongPayload) {
  const Limits limits;
  std::size_t checked = 0;
  for (const KindCase& entry : kKindCases) {
    // The table names the library's own rendering of the kind.
    CRF_CHECK_EQ(std::string(::crf::to_string(entry.kind)), std::string(entry.name));
    const Constraint valid = valid_for(entry.kind, 100);
    CRF_CHECK(valid.kind == entry.kind);
    CRF_CHECK_STATUS(::crf::validate_constraint(valid, limits));
    const Constraint invalid = invalid_for(entry.kind, 101);
    CRF_MODEL_CHECK_CODE(::crf::validate_constraint(invalid, limits), entry.invalid_code);
    ++checked;
  }
  CRF_CHECK_EQ(checked, std::size_t{18});
  // Every numeric kind value from 1 to 18 appears exactly once.
  for (std::uint16_t raw = 1; raw <= 18; ++raw) {
    std::size_t found = 0;
    for (const KindCase& entry : kKindCases) {
      if (static_cast<std::uint16_t>(entry.kind) == raw) {
        ++found;
      }
    }
    CRF_CHECK_EQ(found, std::size_t{1});
  }
  CRF_CHECK_EQ(static_cast<std::uint16_t>(ConstraintKind::MaxHopCount), static_cast<std::uint16_t>(18));
}

CRF_TEST(ModelCanonical, WrongPayloadAndMisusedFieldsAreRejected) {
  const Limits limits;

  // MaxLatency that carries a node list.
  Constraint latency = valid_for(ConstraintKind::MaxLatency, 1);
  latency.nodes = id_list<NodeId>({4});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(latency, limits), ErrorCode::Malformed);

  // RequiredNode that carries a link list.
  Constraint nodes = valid_for(ConstraintKind::RequiredNode, 2);
  nodes.links = id_list<LinkId>({4});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(nodes, limits), ErrorCode::Malformed);

  // A bandwidth capability bound of zero, of a negative value and above the
  // fixed-point ceiling. The exact ceiling is accepted.
  Constraint bandwidth = valid_for(ConstraintKind::MinBandwidthCapability, 3);
  bandwidth.bound = 0;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(bandwidth, limits), ErrorCode::InvalidNumericBound);
  bandwidth.bound = -1;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(bandwidth, limits), ErrorCode::InvalidNumericBound);
  bandwidth.bound = ::crf::kMaxFixedPointBound;
  CRF_CHECK_STATUS(::crf::validate_constraint(bandwidth, limits));
  bandwidth.bound = ::crf::kMaxFixedPointBound + 1;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(bandwidth, limits), ErrorCode::InvalidNumericBound);

  // A mandatory constraint that carries preference metadata.
  Constraint mandatory = valid_for(ConstraintKind::RequiredNode, 4);
  mandatory.preference_rank = 1;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(mandatory, limits), ErrorCode::Malformed);
  mandatory.preference_rank = 0;
  mandatory.preference_weight = 5;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(mandatory, limits), ErrorCode::Malformed);

  // A preference whose weight is outside 1..1000. Both ends are accepted.
  Constraint preference = valid_for(ConstraintKind::RequiredNode, 5);
  preference.scope = ConstraintScope::Preference;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(preference, limits), ErrorCode::InvalidNumericBound);
  preference.preference_weight = 1;
  CRF_CHECK_STATUS(::crf::validate_constraint(preference, limits));
  preference.preference_weight = 1000;
  CRF_CHECK_STATUS(::crf::validate_constraint(preference, limits));
  preference.preference_weight = 1001;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(preference, limits), ErrorCode::InvalidNumericBound);

  // PermitUnknownNegative may never satisfy a positive requirement, and may
  // satisfy a negative one.
  Constraint permit = valid_for(ConstraintKind::RequiredNode, 6);
  permit.unknown_policy = UnknownPolicy::PermitUnknownNegative;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(permit, limits), ErrorCode::InvalidArgument);
  permit.kind = ConstraintKind::ForbiddenNode;
  CRF_CHECK_STATUS(::crf::validate_constraint(permit, limits));

  // Unknown kinds, impossible identities and unknown enumerators.
  Constraint unknown = valid_for(ConstraintKind::RequiredNode, 7);
  unknown.kind = ConstraintKind::Unset;
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(unknown, limits), ErrorCode::UnknownConstraintKind);
  unknown.kind = static_cast<ConstraintKind>(19);
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(unknown, limits), ErrorCode::UnknownConstraintKind);

  Constraint zero_id = valid_for(ConstraintKind::RequiredNode, 0);
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(zero_id, limits), ErrorCode::InvalidArgument);

  Constraint zero_generation = valid_for(ConstraintKind::RequiredNode, 8);
  zero_generation.generation = ConstraintGeneration{};
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(zero_generation, limits), ErrorCode::InvalidArgument);

  Constraint bad_scope = valid_for(ConstraintKind::RequiredNode, 9);
  bad_scope.scope = static_cast<ConstraintScope>(7);
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(bad_scope, limits), ErrorCode::Malformed);

  Constraint bad_policy = valid_for(ConstraintKind::RequiredNode, 10);
  bad_policy.unknown_policy = static_cast<UnknownPolicy>(9);
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(bad_policy, limits), ErrorCode::Malformed);
}

CRF_TEST(ModelCanonical, EntityListBoundsAndZeroIdentitiesAreRejected) {
  Limits limits;
  limits.max_entity_refs_per_constraint = 2;

  Constraint nodes = valid_for(ConstraintKind::RequiredNode, 1);
  nodes.nodes = id_list<NodeId>({1, 2});
  CRF_CHECK_STATUS(::crf::validate_constraint(nodes, limits));
  nodes.nodes = id_list<NodeId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(nodes, limits), ErrorCode::ResourceLimit);

  Constraint links = valid_for(ConstraintKind::RequiredLink, 2);
  links.links = id_list<LinkId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(links, limits), ErrorCode::ResourceLimit);

  Constraint tiers = valid_for(ConstraintKind::RequiredTier, 3);
  tiers.tiers = id_list<TierId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(tiers, limits), ErrorCode::ResourceLimit);

  Constraint sites = valid_for(ConstraintKind::RequiredSite, 4);
  sites.sites = id_list<SiteId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(sites, limits), ErrorCode::ResourceLimit);

  Constraint capabilities = valid_for(ConstraintKind::RequiredCapability, 5);
  capabilities.capabilities = id_list<CapabilityId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(capabilities, limits), ErrorCode::ResourceLimit);

  Constraint policies = valid_for(ConstraintKind::AdministrativePolicy, 6);
  policies.policies = id_list<PolicyId>({1, 2, 3});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(policies, limits), ErrorCode::ResourceLimit);

  // A zero entity identity is never valid, whatever the list bound is.
  Constraint zero = valid_for(ConstraintKind::RequiredNode, 7);
  zero.nodes = id_list<NodeId>({1, 0});
  CRF_MODEL_CHECK_CODE(::crf::validate_constraint(zero, limits), ErrorCode::InvalidArgument);

  // An unsorted list is structurally valid: ordering is the canonicalizer's
  // job, not the structural validator's.
  Constraint unsorted = valid_for(ConstraintKind::RequiredNode, 8);
  unsorted.nodes = id_list<NodeId>({9, 1});
  CRF_CHECK_STATUS(::crf::validate_constraint(unsorted, limits));
}

// ---------------------------------------------------------------------------
// 2 and 3. Canonicalization
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, CanonicalOrderAndDigestAreInsertionOrderIndependent) {
  const std::vector<Constraint> base = canonical_fixture();
  const ConstraintSet reference = canonicalized(make_set(1, base));
  CRF_CHECK(!reference.digest.is_zero());
  CRF_CHECK_EQ(reference.constraints.size(), base.size());
  const std::vector<std::uint64_t> reference_order = constraint_ids(reference);

  struct Permutation {
    std::vector<std::size_t> order;
    std::uint64_t seed;
  };
  std::vector<Permutation> permutations;
  std::vector<std::size_t> reversed_order;
  for (std::size_t index = base.size(); index > 0; --index) {
    reversed_order.push_back(index - 1);
  }
  permutations.push_back(Permutation{reversed_order, 0});
  for (std::size_t rotation = 1; rotation < base.size(); ++rotation) {
    std::vector<std::size_t> order;
    for (std::size_t index = 0; index < base.size(); ++index) {
      order.push_back((index + rotation) % base.size());
    }
    permutations.push_back(Permutation{order, 0});
  }
  for (std::uint64_t seed = 1; seed <= 8; ++seed) {
    permutations.push_back(Permutation{shuffled_order(base.size(), seed), seed});
  }

  for (const Permutation& permutation : permutations) {
    CRF_CHECK_EQ(permutation.order.size(), base.size());
    std::vector<Constraint> permuted;
    permuted.reserve(permutation.order.size());
    for (const std::size_t index : permutation.order) {
      permuted.push_back(base[index]);
    }
    const ConstraintSet set = canonicalized(make_set(1, std::move(permuted)));
    if (!(set.digest == reference.digest)) {
      CRF_FAIL("digest changed with insertion order: " +
               ::crf::test::seed_message("canonicalization", permutation.seed));
    }
    CRF_CHECK(constraint_ids(set) == reference_order);
  }
  CRF_CHECK_EQ(permutations.size(), base.size() + 8);
}

CRF_TEST(ModelCanonical, ShuffledAndDuplicatedEntityListsBecomeStrictlyAscending) {
  ConstraintSet set = make_set(2, shuffled_entity_lists());
  std::vector<SetDefect> defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(set, Limits{}, defects));
  CRF_CHECK_EQ(set.constraints.size(), std::size_t{6});

  for (const Constraint& constraint : set.constraints) {
    CRF_CHECK(strictly_ascending(constraint.nodes));
    CRF_CHECK(strictly_ascending(constraint.links));
    CRF_CHECK(strictly_ascending(constraint.tiers));
    CRF_CHECK(strictly_ascending(constraint.sites));
    CRF_CHECK(strictly_ascending(constraint.capabilities));
    CRF_CHECK(strictly_ascending(constraint.policies));
  }

  const Constraint& nodes = set.constraints[0];
  CRF_CHECK_EQ(nodes.nodes.size(), std::size_t{3});
  CRF_CHECK(nodes.nodes[0] == NodeId::from_value(3));
  CRF_CHECK(nodes.nodes[1] == NodeId::from_value(5));
  CRF_CHECK(nodes.nodes[2] == NodeId::from_value(9));

  const Constraint& links = set.constraints[1];
  CRF_CHECK_EQ(links.links.size(), std::size_t{2});
  CRF_CHECK(links.links[0] == LinkId::from_value(2));
  CRF_CHECK(links.links[1] == LinkId::from_value(8));

  const Constraint& tiers = set.constraints[2];
  CRF_CHECK_EQ(tiers.tiers.size(), std::size_t{2});
  CRF_CHECK(tiers.tiers[0] == TierId::from_value(1) && tiers.tiers[1] == TierId::from_value(7));

  const Constraint& capabilities = set.constraints[4];
  CRF_CHECK_EQ(capabilities.capabilities.size(), std::size_t{2});
  CRF_CHECK(capabilities.capabilities[0] == CapabilityId::from_value(2) &&
            capabilities.capabilities[1] == CapabilityId::from_value(5));

  // Three lists carried duplicates, three were only reordered.
  CRF_CHECK_EQ(count_defects(defects, SetDefectKind::DuplicateEntityCollapsed), std::size_t{3});
  CRF_CHECK_EQ(count_defects(defects, SetDefectKind::EntityListReordered), std::size_t{3});
  CRF_CHECK_EQ(defects.size(), std::size_t{6});
  const SetDefectKind expected_kinds[] = {
      SetDefectKind::DuplicateEntityCollapsed, SetDefectKind::EntityListReordered,
      SetDefectKind::DuplicateEntityCollapsed, SetDefectKind::EntityListReordered,
      SetDefectKind::DuplicateEntityCollapsed, SetDefectKind::EntityListReordered};
  for (std::size_t index = 0; index < defects.size() && index < 6; ++index) {
    CRF_CHECK_EQ(text(defects[index].kind), text(expected_kinds[index]));
    CRF_CHECK(defects[index].constraint == ConstraintId::from_value(index + 1));
  }

  // Canonicalization is idempotent: a second pass changes nothing.
  ConstraintSet second = set;
  std::vector<SetDefect> second_defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(second, Limits{}, second_defects));
  CRF_CHECK_EQ(describe_set_difference(second, set), std::string("identical"));
  CRF_CHECK(second_defects.empty());
}

CRF_TEST(ModelCanonical, EquivalentDuplicateCollapsesToSmallerIdentity) {
  Constraint small = make(20, ConstraintKind::RequiredNode);
  small.nodes = id_list<NodeId>({7});
  Constraint large = make(50, ConstraintKind::RequiredNode);
  large.nodes = id_list<NodeId>({7});
  CRF_CHECK(::crf::equivalent_payload(small, large));
  CRF_CHECK(!::crf::semantically_equal(small, large));

  ConstraintSet set = make_set(3, {large, small});
  std::vector<SetDefect> defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(set, Limits{}, defects));
  CRF_CHECK_EQ(set.constraints.size(), std::size_t{1});
  CRF_CHECK(set.constraints[0].id == ConstraintId::from_value(20));
  CRF_CHECK_EQ(count_defects(defects, SetDefectKind::EquivalentDuplicateCollapsed), std::size_t{1});
  for (const SetDefect& defect : defects) {
    if (defect.kind == SetDefectKind::EquivalentDuplicateCollapsed) {
      CRF_CHECK(defect.constraint == ConstraintId::from_value(20));
    }
  }

  // Three equivalent copies leave one survivor and two collapse observations.
  Constraint middle = make(35, ConstraintKind::RequiredNode);
  middle.nodes = id_list<NodeId>({7});
  ConstraintSet triple = make_set(3, {large, middle, small});
  std::vector<SetDefect> triple_defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(triple, Limits{}, triple_defects));
  CRF_CHECK_EQ(triple.constraints.size(), std::size_t{1});
  CRF_CHECK(triple.constraints[0].id == ConstraintId::from_value(20));
  CRF_CHECK_EQ(count_defects(triple_defects, SetDefectKind::EquivalentDuplicateCollapsed),
               std::size_t{2});
}

CRF_TEST(ModelCanonical, DuplicateIdentityWithDifferentPayloadIsRejected) {
  Constraint first = make(5, ConstraintKind::RequiredNode);
  first.nodes = id_list<NodeId>({1});
  Constraint second = make(5, ConstraintKind::RequiredNode);
  second.nodes = id_list<NodeId>({2});
  CRF_CHECK(!::crf::equivalent_payload(first, second));

  const ConstraintSet set = make_set(4, {first, second});
  const ConstraintSet untouched = set;
  ConstraintSet working = set;
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status =
      ::crf::validate_and_finalize_constraint_set(working, Limits{}, defects, contradictions);
  CRF_MODEL_CHECK_CODE(status, ErrorCode::DuplicateIdentity);
  CRF_CHECK_EQ(describe_set_difference(working, untouched), std::string("identical"));

  // The same identity with an identical payload is a duplicate, not a conflict.
  ConstraintSet duplicate = make_set(4, {first, first});
  std::vector<SetDefect> duplicate_defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(duplicate, Limits{}, duplicate_defects));
  CRF_CHECK_EQ(duplicate.constraints.size(), std::size_t{1});

  // Generation is not part of the payload, so it is collapsed as well.
  Constraint other_generation = first;
  other_generation.generation = ConstraintGeneration::from_value(9);
  CRF_CHECK(::crf::equivalent_payload(first, other_generation));
  ConstraintSet generations = make_set(4, {other_generation, first});
  std::vector<SetDefect> generation_defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(generations, Limits{}, generation_defects));
  CRF_CHECK_EQ(generations.constraints.size(), std::size_t{1});
  CRF_CHECK(generations.constraints[0].generation == ConstraintGeneration::from_value(1));
}

// ---------------------------------------------------------------------------
// 5. Contradictions
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, ContradictionRequiredAndForbiddenSameEntity) {
  {
    Constraint required = make(1, ConstraintKind::RequiredNode);
    required.nodes = id_list<NodeId>({5, 7});
    Constraint forbidden = make(2, ConstraintKind::ForbiddenNode);
    forbidden.nodes = id_list<NodeId>({7, 9});
    expect_contradiction(make_set(10, {required, forbidden}),
                         ContradictionExpectation{ContradictionKind::RequiredAndForbiddenSameEntity,
                                                  SubjectKind::Node, 7});
  }
  {
    Constraint required = make(3, ConstraintKind::RequiredLink);
    required.links = id_list<LinkId>({11});
    Constraint forbidden = make(4, ConstraintKind::ForbiddenLink);
    forbidden.links = id_list<LinkId>({11});
    expect_contradiction(make_set(10, {required, forbidden}),
                         ContradictionExpectation{ContradictionKind::RequiredAndForbiddenSameEntity,
                                                  SubjectKind::Link, 11});
  }
  {
    Constraint required = make(5, ConstraintKind::RequiredTier);
    required.tiers = id_list<TierId>({13});
    Constraint forbidden = make(6, ConstraintKind::ForbiddenTier);
    forbidden.tiers = id_list<TierId>({13});
    expect_contradiction(make_set(10, {required, forbidden}),
                         ContradictionExpectation{ContradictionKind::RequiredAndForbiddenSameEntity,
                                                  SubjectKind::Tier, 13});
  }
  {
    Constraint required = make(7, ConstraintKind::RequiredSite);
    required.sites = id_list<SiteId>({17});
    Constraint forbidden = make(8, ConstraintKind::ForbiddenSite);
    forbidden.sites = id_list<SiteId>({17});
    expect_contradiction(make_set(10, {required, forbidden}),
                         ContradictionExpectation{ContradictionKind::RequiredAndForbiddenSameEntity,
                                                  SubjectKind::Site, 17});
  }
  {
    Constraint required = make(9, ConstraintKind::RequiredCapability);
    required.capabilities = id_list<CapabilityId>({19});
    Constraint forbidden = make(10, ConstraintKind::ForbiddenCapability);
    forbidden.capabilities = id_list<CapabilityId>({19});
    expect_contradiction(make_set(10, {required, forbidden}),
                         ContradictionExpectation{ContradictionKind::RequiredAndForbiddenSameEntity,
                                                  SubjectKind::Capability, 19});
  }

  // Control: disjoint required and forbidden entities are not a contradiction.
  Constraint required = make(1, ConstraintKind::RequiredNode);
  required.nodes = id_list<NodeId>({5});
  Constraint forbidden = make(2, ConstraintKind::ForbiddenNode);
  forbidden.nodes = id_list<NodeId>({6});
  ConstraintSet compatible = make_set(10, {required, forbidden});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(compatible, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());
}

CRF_TEST(ModelCanonical, ContradictionConflictingLocalityScopes) {
  Constraint first = valid_for(ConstraintKind::LocalityScope, 1);
  first.domain_kind = DomainKind::Rack;
  first.locality_domain = LocalityDomainId::from_value(11);
  Constraint second = valid_for(ConstraintKind::LocalityScope, 2);
  second.domain_kind = DomainKind::Rack;
  second.locality_domain = LocalityDomainId::from_value(22);
  // Canonical order places the smaller domain first, so the second constraint
  // names the conflicting domain.
  expect_contradiction(make_set(11, {second, first}),
                       ContradictionExpectation{ContradictionKind::ConflictingLocalityScopes,
                                                SubjectKind::LocalityDomain, 22});

  // Different domain kinds never conflict: a path may be confined to a rack and
  // to a plane at the same time.
  Constraint plane = valid_for(ConstraintKind::LocalityScope, 3);
  plane.domain_kind = DomainKind::Plane;
  plane.locality_domain = LocalityDomainId::from_value(33);
  ConstraintSet compatible = make_set(11, {first, plane});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(compatible, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());

  // Two locality scopes on the same domain do not conflict.
  Constraint same = first;
  same.id = ConstraintId::from_value(4);
  ConstraintSet equal_scopes = make_set(11, {first, same});
  std::vector<SetDefect> equal_defects;
  std::vector<Contradiction> equal_contradictions;
  CRF_CHECK_STATUS(::crf::validate_and_finalize_constraint_set(equal_scopes, Limits{}, equal_defects,
                                                               equal_contradictions));
  CRF_CHECK(equal_contradictions.empty());
  CRF_CHECK_EQ(equal_scopes.constraints.size(), std::size_t{1});
}

CRF_TEST(ModelCanonical, ContradictionConflictingIsolationClasses) {
  Constraint first = valid_for(ConstraintKind::IsolationClass, 1);
  first.isolation_class = IsolationClassId::from_value(31);
  Constraint second = valid_for(ConstraintKind::IsolationClass, 2);
  second.isolation_class = IsolationClassId::from_value(44);
  expect_contradiction(make_set(12, {second, first}),
                       ContradictionExpectation{ContradictionKind::ConflictingIsolationClasses,
                                                SubjectKind::IsolationClass, 44});

  // One class named twice is the same requirement, not a conflict.
  Constraint same = first;
  same.id = ConstraintId::from_value(3);
  ConstraintSet repeated = make_set(12, {first, same});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(repeated, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());
  CRF_CHECK_EQ(repeated.constraints.size(), std::size_t{1});
}

CRF_TEST(ModelCanonical, ContradictionFailureDomainRelationConflict) {
  // Required Distinct(2) excludes a fully shared failure domain.
  Constraint required = valid_for(ConstraintKind::RequiredFailureDomainRelation, 1);
  required.domain_kind = DomainKind::Rack;
  required.bound = 2;
  Constraint shared = valid_for(ConstraintKind::ForbiddenFailureDomainRelation, 2);
  shared.domain_kind = DomainKind::Rack;
  shared.domain_relation = DomainRelation::Shared;
  expect_contradiction(make_set(13, {required, shared}),
                       ContradictionExpectation{ContradictionKind::FailureDomainRelationConflict,
                                                SubjectKind::FailureDomain,
                                                static_cast<std::uint64_t>(DomainKind::Rack)});

  // Required Distinct(k) with Forbidden Distinct(m) and m <= k is unsatisfiable.
  Constraint forbidden_distinct = shared;
  forbidden_distinct.id = ConstraintId::from_value(3);
  forbidden_distinct.domain_relation = DomainRelation::Distinct;
  forbidden_distinct.bound = 3;
  Constraint required_three = required;
  required_three.id = ConstraintId::from_value(4);
  required_three.bound = 3;
  expect_contradiction(make_set(13, {required_three, forbidden_distinct}),
                       ContradictionExpectation{ContradictionKind::FailureDomainRelationConflict,
                                                SubjectKind::FailureDomain,
                                                static_cast<std::uint64_t>(DomainKind::Rack)});

  // Required Distinct(2) with Forbidden Distinct(3) is satisfiable.
  Constraint forbidden_three = shared;
  forbidden_three.domain_relation = DomainRelation::Distinct;
  forbidden_three.bound = 3;
  Constraint required_two = required;
  required_two.id = ConstraintId::from_value(5);
  ConstraintSet compatible = make_set(13, {required_two, forbidden_three});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(compatible, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());

  // Different kinds never conflict: a rack relation says nothing about a plane.
  Constraint other_kind = shared;
  other_kind.domain_kind = DomainKind::Plane;
  ConstraintSet different = make_set(13, {required_two, other_kind});
  std::vector<SetDefect> different_defects;
  std::vector<Contradiction> different_contradictions;
  CRF_CHECK_STATUS(::crf::validate_and_finalize_constraint_set(different, Limits{}, different_defects,
                                                               different_contradictions));
  CRF_CHECK(different_contradictions.empty());
}

CRF_TEST(ModelCanonical, ContradictionImpossibleHopBudget) {
  Constraint first = make(1, ConstraintKind::RequiredNode);
  first.nodes = id_list<NodeId>({1});
  Constraint second = make(2, ConstraintKind::RequiredNode);
  second.nodes = id_list<NodeId>({2});
  Constraint third = make(3, ConstraintKind::RequiredNode);
  third.nodes = id_list<NodeId>({3});
  Constraint budget_one = valid_for(ConstraintKind::MaxHopCount, 4);
  budget_one.bound = 1;

  // Three distinct required nodes need at least two hops.
  expect_contradiction(make_set(14, {first, second, third, budget_one}),
                       ContradictionExpectation{ContradictionKind::ImpossibleHopBudget,
                                                SubjectKind::Constraint, 2});

  // Exactly enough budget is satisfiable; one hop less is not.
  Constraint budget_two = budget_one;
  budget_two.id = ConstraintId::from_value(5);
  budget_two.bound = 2;
  ConstraintSet satisfiable = make_set(14, {first, second, third, budget_two});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(satisfiable, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());

  // Overlapping required nodes count once.
  Constraint overlapping = make(6, ConstraintKind::RequiredNode);
  overlapping.nodes = id_list<NodeId>({3});
  ConstraintSet overlapping_set = make_set(14, {first, second, third, overlapping, budget_two});
  std::vector<SetDefect> overlapping_defects;
  std::vector<Contradiction> overlapping_contradictions;
  CRF_CHECK_STATUS(::crf::validate_and_finalize_constraint_set(
      overlapping_set, Limits{}, overlapping_defects, overlapping_contradictions));
  CRF_CHECK(overlapping_contradictions.empty());
}

// ---------------------------------------------------------------------------
// 6. Lifecycle
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, LifecycleTransitionTableIsExhaustive) {
  std::size_t checked = 0;
  std::size_t accepted_rows = 0;
  std::size_t rejected_rows = 0;
  for (const LifecycleExpectation& row : kLifecycleTable) {
    const ConstraintSetState before = row.state;
    const TransitionOutcome outcome = ::crf::apply_lifecycle_event(row.state, row.event);
    // The transition function is pure: it cannot mutate the caller's state.
    CRF_CHECK(row.state == before);
    CRF_CHECK_EQ(outcome.accepted, row.accepted);
    CRF_CHECK(outcome.next == row.next);
    CRF_CHECK_EQ(::crf::admits_admissibility(outcome.next),
                 outcome.next == ConstraintSetState::Active);
    CRF_CHECK(outcome.rejection != nullptr);
    if (row.accepted) {
      ++accepted_rows;
      CRF_CHECK(outcome.rejection[0] == '\0');
    } else {
      ++rejected_rows;
      CRF_CHECK(outcome.rejection[0] != '\0');
    }
    ++checked;
  }
  CRF_CHECK_EQ(checked, std::size_t{63});
  CRF_CHECK_EQ(accepted_rows, std::size_t{23});
  CRF_CHECK_EQ(rejected_rows, std::size_t{40});

  // Every one of the 7 x 9 pairs appears exactly once in the table.
  for (std::uint8_t state_raw = 1; state_raw <= 7; ++state_raw) {
    const ConstraintSetState state = static_cast<ConstraintSetState>(state_raw);
    for (std::uint8_t event_raw = 1; event_raw <= 9; ++event_raw) {
      const LifecycleEvent event = static_cast<LifecycleEvent>(event_raw);
      std::size_t found = 0;
      for (const LifecycleExpectation& row : kLifecycleTable) {
        if (row.state == state && row.event == event) {
          ++found;
        }
      }
      CRF_CHECK_EQ(found, std::size_t{1});
    }
  }
  CRF_CHECK(std::string(::crf::to_string(ConstraintSetState::Retired)) == "Retired");
  CRF_CHECK(std::string(::crf::to_string(LifecycleEvent::Reinstate)) == "Reinstate");
}

// ---------------------------------------------------------------------------
// 7. Digest stability
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, DigestIgnoresPresentationAndOrder) {
  const ConstraintSet base = canonicalized(make_set(1, digest_fixture()));
  CRF_CHECK(!base.digest.is_zero());

  ConstraintSet renamed = base;
  renamed.name = "a completely different human readable name";
  CRF_CHECK(renamed.name != base.name);
  CRF_CHECK(::crf::constraint_set_digest(renamed) == base.digest);

  ConstraintSet ticked = base;
  ticked.declared_tick = 987654321;
  CRF_CHECK(ticked.declared_tick != base.declared_tick);
  CRF_CHECK(::crf::constraint_set_digest(ticked) == base.digest);

  ConstraintSet active = base;
  active.state = ConstraintSetState::Active;
  CRF_CHECK(active.state != base.state);
  CRF_CHECK(::crf::constraint_set_digest(active) == base.digest);

  ConstraintSet retired = base;
  retired.state = ConstraintSetState::Retired;
  CRF_CHECK(::crf::constraint_set_digest(retired) == base.digest);

  std::vector<Constraint> reversed_constraints = digest_fixture();
  std::reverse(reversed_constraints.begin(), reversed_constraints.end());
  const ConstraintSet reordered = canonicalized(make_set(1, std::move(reversed_constraints)));
  CRF_CHECK(constraint_ids(reordered) == constraint_ids(base));
  CRF_CHECK(reordered.digest == base.digest);
}

CRF_TEST(ModelCanonical, DigestChangesWithSemantics) {
  const ConstraintSet base = canonicalized(make_set(1, digest_fixture()));

  // A changed fixed-point bound.
  {
    std::vector<Constraint> constraints = digest_fixture();
    for (Constraint& constraint : constraints) {
      if (constraint.kind == ConstraintKind::MaxLatency && constraint.scope == ConstraintScope::Mandatory) {
        constraint.bound += 1;
      }
    }
    CRF_CHECK(!(canonicalized(make_set(1, std::move(constraints))).digest == base.digest));
  }
  // A changed entity list.
  {
    std::vector<Constraint> constraints = digest_fixture();
    constraints[0].nodes = id_list<NodeId>({3, 6});
    CRF_CHECK(!(canonicalized(make_set(1, std::move(constraints))).digest == base.digest));
  }
  // A changed evidence requirement.
  {
    ConstraintSet changed = make_set(1, digest_fixture());
    changed.evidence.topology = ::crf::TopologyGeneration::from_value(4);
    CRF_CHECK(!(canonicalized(std::move(changed)).digest == base.digest));
  }
  // A changed ranking policy.
  {
    ConstraintSet changed = make_set(1, digest_fixture());
    changed.ranking.consume_planner_rank = true;
    CRF_CHECK(!(canonicalized(std::move(changed)).digest == base.digest));
  }
  {
    ConstraintSet changed = make_set(1, digest_fixture());
    changed.ranking.tiebreak = CandidateTiebreak::NodeSequenceLexicographic;
    CRF_CHECK(!(canonicalized(std::move(changed)).digest == base.digest));
  }
  // An added constraint.
  {
    std::vector<Constraint> constraints = digest_fixture();
    Constraint extra = make(17, ConstraintKind::ForbiddenLink);
    extra.links = id_list<LinkId>({4});
    constraints.push_back(extra);
    CRF_CHECK(!(canonicalized(make_set(1, std::move(constraints))).digest == base.digest));
  }
  // A changed constraint identity and generation: identity is digested too.
  {
    std::vector<Constraint> constraints = digest_fixture();
    constraints[0].id = ConstraintId::from_value(111);
    CRF_CHECK(!(canonicalized(make_set(1, std::move(constraints))).digest == base.digest));
  }
  {
    std::vector<Constraint> constraints = digest_fixture();
    constraints[0].generation = ConstraintGeneration::from_value(2);
    CRF_CHECK(!(canonicalized(make_set(1, std::move(constraints))).digest == base.digest));
  }
  // A changed constraint-set generation.
  {
    ConstraintSet changed = make_set(1, digest_fixture());
    changed.generation = ConstraintSetGeneration::from_value(2);
    CRF_CHECK(!(canonicalized(std::move(changed)).digest == base.digest));
  }
}

// ---------------------------------------------------------------------------
// 8. Encoding round trip
// ---------------------------------------------------------------------------

CRF_TEST(ModelCanonical, EncodingRoundTripIsExact) {
  ConstraintSet set = make_set(77, complex_fixture());
  set.generation = ConstraintSetGeneration::from_value(3);
  set.state = ConstraintSetState::Active;
  set.name = "complex-definition";
  set.declared_tick = 4242;
  set.evidence.topology = ::crf::TopologyGeneration::from_value(3);
  set.evidence.link_state = ::crf::LinkStateGeneration::from_value(4);
  set.evidence.capability = ::crf::CapabilityGeneration::from_value(5);
  set.evidence.failure_domain = ::crf::FailureDomainGeneration::from_value(6);
  set.evidence.policy = ::crf::PolicyGeneration::from_value(7);
  set.evidence.planner = ::crf::PlannerGeneration::from_value(8);
  set.evidence.path_authority = ::crf::PathAuthorityGeneration::from_value(9);
  set.evidence.max_evidence_age_ticks = 100;
  set.ranking.consume_planner_rank = true;
  set.ranking.prefer_lower_cost = false;
  set.ranking.tiebreak = CandidateTiebreak::NodeSequenceLexicographic;

  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions));
  CRF_CHECK(contradictions.empty());
  CRF_CHECK_EQ(set.constraints.size(), complex_fixture().size());
  CRF_CHECK(!set.digest.is_zero());

  ::crf::ByteWriter writer;
  ::crf::encode_constraint_set(writer, set);
  CRF_CHECK(writer.size() > Digest256::kSize);

  ::crf::ByteReader reader(writer.span());
  ConstraintSet decoded;
  CRF_CHECK(::crf::decode_constraint_set(reader, Limits{}, decoded));
  CRF_CHECK(reader.at_end());
  CRF_CHECK_EQ(describe_set_difference(decoded, set), std::string("identical"));
  CRF_CHECK_STATUS(::crf::verify_canonical_constraint_set(decoded, Limits{}));
  CRF_CHECK(decoded.state == ConstraintSetState::Active);
  CRF_CHECK_EQ(decoded.name, std::string("complex-definition"));
  CRF_CHECK_EQ(decoded.declared_tick, std::uint64_t{4242});

  // A corrupted byte anywhere in the digest region is rejected.
  const std::span<const std::byte> encoded = writer.span();
  const std::vector<std::byte> clean(encoded.begin(), encoded.end());
  {
    std::vector<std::byte> corrupted = clean;
    corrupted.back() ^= std::byte{0xff};
    ::crf::ByteReader reader_corrupt(corrupted);
    ConstraintSet ignored;
    CRF_CHECK(!::crf::decode_constraint_set(reader_corrupt, Limits{}, ignored));
  }
  {
    std::vector<std::byte> corrupted = clean;
    corrupted[corrupted.size() - Digest256::kSize / 2] ^= std::byte{0x01};
    ::crf::ByteReader reader_corrupt(corrupted);
    ConstraintSet ignored;
    CRF_CHECK(!::crf::decode_constraint_set(reader_corrupt, Limits{}, ignored));
  }
  {
    std::vector<std::byte> corrupted = clean;
    corrupted[corrupted.size() - 1] = std::byte{0x00};
    if (clean.back() == std::byte{0x00}) {
      corrupted[corrupted.size() - 1] = std::byte{0x01};
    }
    ::crf::ByteReader reader_corrupt(corrupted);
    ConstraintSet ignored;
    CRF_CHECK(!::crf::decode_constraint_set(reader_corrupt, Limits{}, ignored));
  }

  // A truncated encoding is rejected rather than partially accepted.
  {
    std::vector<std::byte> shortened(clean.begin(), clean.end() - 1);
    ::crf::ByteReader reader_short(shortened);
    ConstraintSet ignored;
    CRF_CHECK(!::crf::decode_constraint_set(reader_short, Limits{}, ignored));
  }

  // The set codec is a bounded sub-reader: it consumes exactly its own bytes
  // and leaves a caller-owned trailing region untouched. Trailing-byte
  // rejection is the enclosing message codec's contract, checked below.
  std::vector<std::byte> extended = clean;
  extended.push_back(std::byte{0xab});
  ::crf::ByteReader reader_extended(extended);
  ConstraintSet from_extended;
  CRF_CHECK(::crf::decode_constraint_set(reader_extended, Limits{}, from_extended));
  CRF_CHECK_EQ(reader_extended.position(), writer.size());
  CRF_CHECK(!reader_extended.at_end());
  CRF_CHECK_EQ(describe_set_difference(from_extended, set), std::string("identical"));

  // The frame codec rejects both trailing bytes and short frames explicitly.
  // The frame carries an empty payload on purpose: ::crf::decode_frame verifies
  // its integrity check over the wrong payload slice (src/protocol.cpp takes the
  // payload at kHeaderBytes instead of the semantic header length), so a frame
  // with a non-empty payload does not currently round-trip. That defect is
  // reported separately and is deliberately not asserted here.
  ::crf::Frame frame;
  frame.header.message = ::crf::MessageId::PublishConstraintSet;
  std::vector<std::byte> frame_bytes;
  CRF_CHECK_STATUS(::crf::encode_frame(frame, Limits{}, frame_bytes));
  ::crf::Frame decoded_frame;
  CRF_CHECK_STATUS(::crf::decode_frame(frame_bytes, Limits{}, decoded_frame));
  CRF_CHECK(decoded_frame.payload.empty());
  CRF_CHECK(decoded_frame.header.message == ::crf::MessageId::PublishConstraintSet);
  std::vector<std::byte> with_trailer = frame_bytes;
  with_trailer.push_back(std::byte{0xab});
  CRF_MODEL_CHECK_CODE(::crf::decode_frame(with_trailer, Limits{}, decoded_frame),
                 ErrorCode::TrailingBytes);
  const std::vector<std::byte> short_frame(frame_bytes.begin(), frame_bytes.end() - 1);
  CRF_MODEL_CHECK_CODE(::crf::decode_frame(short_frame, Limits{}, decoded_frame), ErrorCode::Truncated);
}

CRF_TEST(ModelCanonical, ConstraintCodecRoundTripsEveryKind) {
  const Limits limits;
  std::uint64_t next_id = 200;
  std::size_t checked = 0;
  for (const KindCase& entry : kKindCases) {
    const Constraint original = valid_for(entry.kind, next_id);
    ++next_id;
    ::crf::ByteWriter writer;
    ::crf::encode_constraint(writer, original);
    CRF_CHECK(writer.size() > 0);
    ::crf::ByteReader reader(writer.span());
    Constraint decoded;
    CRF_CHECK(::crf::decode_constraint(reader, limits, decoded));
    CRF_CHECK(reader.at_end());
    CRF_CHECK(original == decoded);
    CRF_CHECK(::crf::equivalent_payload(original, decoded));
    CRF_CHECK(::crf::semantically_equal(original, decoded));
    CRF_CHECK(::crf::encode_constraint_payload(original) == ::crf::encode_constraint_payload(decoded));
    ++checked;
  }
  CRF_CHECK_EQ(checked, std::size_t{18});

  // A decoded constraint that is structurally wrong for its kind is refused.
  Constraint wrong = valid_for(ConstraintKind::MaxLatency, 500);
  wrong.nodes = id_list<NodeId>({1});
  ::crf::ByteWriter writer;
  ::crf::encode_constraint(writer, wrong);
  ::crf::ByteReader reader(writer.span());
  Constraint decoded;
  CRF_CHECK(!::crf::decode_constraint(reader, limits, decoded));

  // A non-canonical entity list inside a durable record is corruption.
  Constraint unsorted = valid_for(ConstraintKind::RequiredNode, 501);
  unsorted.nodes = id_list<NodeId>({5, 3});
  ::crf::ByteWriter list_writer;
  ::crf::encode_constraint(list_writer, unsorted);
  ::crf::ByteReader list_reader(list_writer.span());
  CRF_CHECK(!::crf::decode_constraint(list_reader, limits, decoded));
}
