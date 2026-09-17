// Constraint Routing Fabric -- independent bounded evaluation oracle.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This file deliberately does NOT call the production evaluator. It restates
// the documented evaluation precedence in a small, independent implementation
// and cross-checks the two on randomized candidate populations.
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "constraint_routing_fabric/evaluator.hpp"
#include "constraint_routing_fabric/ordering.hpp"
#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

// --- oracle-local reason model ----------------------------------------------

struct OracleReason {
  ReasonCode code{ReasonCode::None};
  std::uint8_t klass{0};
  std::uint32_t ordinal{0};
  ConstraintId constraint{};
  std::uint64_t subject{0};
  std::uint64_t expected{0};
  std::uint64_t actual{0};
};

/// Independent restatement of the reason-class precedence table.
[[nodiscard]] std::uint8_t oracle_class(ReasonCode code) {
  const std::uint16_t value = static_cast<std::uint16_t>(code);
  if (value >= 100 && value < 200) return 0;
  if (value >= 200 && value < 300) return 1;
  if (value >= 300 && value < 400) return 2;
  if (value >= 400 && value < 500) return 3;
  if (value >= 500 && value < 600) return 4;
  if (value >= 600 && value < 700) return 5;
  if (value >= 700 && value < 800) return 6;
  if (value >= 800 && value < 900) return 7;
  return 8;
}

[[nodiscard]] int oracle_compare(const OracleReason& a, const OracleReason& b) {
  if (a.klass != b.klass) return a.klass < b.klass ? -1 : 1;
  if (a.ordinal != b.ordinal) return a.ordinal < b.ordinal ? -1 : 1;
  if (a.code != b.code) return a.code < b.code ? -1 : 1;
  if (a.constraint != b.constraint) return a.constraint < b.constraint ? -1 : 1;
  if (a.subject != b.subject) return a.subject < b.subject ? -1 : 1;
  if (a.expected != b.expected) return a.expected < b.expected ? -1 : 1;
  if (a.actual != b.actual) return a.actual < b.actual ? -1 : 1;
  return 0;
}

struct OracleResult {
  Outcome outcome{Outcome::Malformed};
  ReasonCode primary{ReasonCode::None};
  std::vector<OracleReason> reasons{};
};

/// Independent restatement of the documented reason-code to outcome-class
/// mapping. The mapping is not a function of the reason class alone: several
/// mandatory-constraint codes report UNKNOWN_REQUIRED_EVIDENCE rather than a
/// hard failure, because the constraint could not be decided at all.
[[nodiscard]] Outcome oracle_outcome(ReasonCode code) {
  switch (code) {
    case ReasonCode::None: return Outcome::Admissible;
    case ReasonCode::ResourceLimitExceeded:
    case ReasonCode::BatchTooLarge:
    case ReasonCode::TooManyConstraints:
    case ReasonCode::TooManyCandidates:
    case ReasonCode::TooManyEntityRefs:
    case ReasonCode::ExplanationTruncated:
    case ReasonCode::HistoryLimitReached:
      return Outcome::ResourceLimit;
    case ReasonCode::MalformedFrame:
    case ReasonCode::UnsupportedProtocolVersion:
    case ReasonCode::UnknownMessageId:
    case ReasonCode::TrailingBytes:
    case ReasonCode::OversizedVector:
    case ReasonCode::IntegrityMismatch:
    case ReasonCode::MalformedConstraint:
    case ReasonCode::MalformedCandidate:
    case ReasonCode::UnsupportedVersion:
      return Outcome::Malformed;
    case ReasonCode::UnknownPublisher:
    case ReasonCode::PublisherNotRegistered:
    case ReasonCode::SessionFenced:
    case ReasonCode::ScopeNotAuthorized:
    case ReasonCode::MissingAuthorityContext:
    case ReasonCode::MutationAttemptConflict:
    case ReasonCode::StaleCoordinatorEpoch:
    case ReasonCode::FutureCoordinatorEpoch:
    case ReasonCode::FencedWorkerBoot:
    case ReasonCode::UnknownWorkerBoot:
    case ReasonCode::WorkerBootReused:
    case ReasonCode::PathNotLegal:
    case ReasonCode::ConstraintSetRevoked:
      return Outcome::Unauthorized;
    case ReasonCode::PathAuthorityNotEvaluated:
    case ReasonCode::PathAuthorityGenerationMissing:
    case ReasonCode::PlannerCostModelMismatch:
    case ReasonCode::UnknownRequiredEvidence:
    case ReasonCode::LatencyEvidenceUnavailable:
    case ReasonCode::BandwidthCapabilityUnavailable:
    case ReasonCode::TierEvidenceUnavailable:
    case ReasonCode::SiteEvidenceUnavailable:
    case ReasonCode::LocalityEvidenceUnavailable:
    case ReasonCode::IsolationEvidenceUnavailable:
    case ReasonCode::CapabilityEvidenceUnavailable:
    case ReasonCode::FailureDomainEvidenceUnavailable:
    case ReasonCode::PolicyEvidenceUnavailable:
      return Outcome::UnknownRequiredEvidence;
    case ReasonCode::StalePathAuthority: return Outcome::StalePathAuthority;
    case ReasonCode::ConstraintSetNotFound:
    case ReasonCode::ConstraintSetNotActive:
    case ReasonCode::ConstraintSetSuspended:
    case ReasonCode::ConstraintSetSuperseded:
    case ReasonCode::ConstraintSetRetired:
    case ReasonCode::StaleConstraintSetGeneration:
    case ReasonCode::ContradictoryConstraintSet:
      return Outcome::StaleConstraintSet;
    case ReasonCode::ConstraintSetRevalidationRequired: return Outcome::RevalidationRequired;
    case ReasonCode::StaleTopologyEvidence:
    case ReasonCode::StaleLinkStateEvidence:
    case ReasonCode::StaleCapabilityEvidence:
    case ReasonCode::StaleFailureDomainEvidence:
    case ReasonCode::StalePolicyEvidence:
    case ReasonCode::StalePlannerEvidence:
    case ReasonCode::EvidenceAgeExceeded:
    case ReasonCode::EvidenceNotBound:
      return Outcome::StaleEvidence;
    default:
      break;
  }
  switch (code) {
    case ReasonCode::LatencyEvidenceUnavailable:
    case ReasonCode::BandwidthCapabilityUnavailable:
    case ReasonCode::TierEvidenceUnavailable:
    case ReasonCode::SiteEvidenceUnavailable:
    case ReasonCode::LocalityEvidenceUnavailable:
    case ReasonCode::IsolationEvidenceUnavailable:
    case ReasonCode::CapabilityEvidenceUnavailable:
    case ReasonCode::FailureDomainEvidenceUnavailable:
    case ReasonCode::PolicyEvidenceUnavailable:
      return Outcome::UnknownRequiredEvidence;
    default:
      break;
  }
  return Outcome::HardConstraintFailed;
}

[[nodiscard]] bool oracle_family_consulted(const ConstraintSet& set, EvidenceFamily family) {
  if (family == EvidenceFamily::PathAuthority) {
    return true;
  }
  for (const Constraint& constraint : set.constraints) {
    if (constraint.kind == ConstraintKind::MaxLatency) {
      const EvidenceFamily wanted = constraint.latency_source == LatencySource::PlannerCost
                                        ? EvidenceFamily::Planner
                                        : EvidenceFamily::LinkState;
      if (wanted == family) return true;
      continue;
    }
    if ((evidence_families(constraint.kind) & family_bit(family)) != 0) {
      return true;
    }
  }
  if (family == EvidenceFamily::Planner && set.ranking.consume_planner_cost) {
    return true;
  }
  return false;
}

[[nodiscard]] std::uint64_t oracle_required(const EvidenceRequirements& evidence, EvidenceFamily family) {
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

[[nodiscard]] std::uint64_t oracle_bound(const EvidenceGenerationSet& evidence, EvidenceFamily family) {
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

[[nodiscard]] ReasonCode oracle_stale_code(EvidenceFamily family) {
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

[[nodiscard]] bool oracle_has_node(const CandidatePath& candidate, NodeId node) {
  return std::any_of(candidate.nodes.begin(), candidate.nodes.end(),
                     [node](const NodeFact& fact) { return fact.node == node; });
}

[[nodiscard]] bool oracle_has_link(const CandidatePath& candidate, LinkId link) {
  return std::any_of(candidate.links.begin(), candidate.links.end(),
                     [link](const LinkFact& fact) { return fact.link == link; });
}

struct OracleEntity {
  std::uint64_t identity{0};
  const std::vector<FailureDomainRef>* domains{nullptr};
  const std::vector<CapabilityRef>* capabilities{nullptr};
  const std::vector<IsolationAttestation>* isolation{nullptr};
};

[[nodiscard]] std::vector<OracleEntity> oracle_entities(const CandidatePath& candidate) {
  std::vector<OracleEntity> entities;
  for (const NodeFact& node : candidate.nodes) {
    entities.push_back(OracleEntity{node.node.value(), &node.domains, &node.capabilities, &node.isolation});
  }
  for (const LinkFact& link : candidate.links) {
    entities.push_back(OracleEntity{link.link.value(), &link.domains, &link.capabilities, &link.isolation});
  }
  return entities;
}

[[nodiscard]] int oracle_capability_generation(const std::vector<CapabilityRef>& refs,
                                               CapabilityId wanted) {
  for (const CapabilityRef& ref : refs) {
    if (ref.capability == wanted) {
      return static_cast<int>(ref.generation.value());
    }
  }
  return -1;
}

/// The oracle pipeline. Same specification, independent implementation.
[[nodiscard]] OracleResult oracle_evaluate(const ConstraintSet& set, const CandidatePath& candidate,
                                           const EvidenceRequirements& required) {
  OracleResult result;
  const auto add = [&result](ReasonCode code, std::uint32_t ordinal, ConstraintId constraint,
                             std::uint64_t subject, std::uint64_t expected, std::uint64_t actual) {
    result.reasons.push_back(
        OracleReason{code, oracle_class(code), ordinal, constraint, subject, expected, actual});
  };

  if (set.state != ConstraintSetState::Active) {
    ReasonCode code = ReasonCode::ConstraintSetNotActive;
    switch (set.state) {
      case ConstraintSetState::Suspended: code = ReasonCode::ConstraintSetSuspended; break;
      case ConstraintSetState::RevalidationRequired:
        code = ReasonCode::ConstraintSetRevalidationRequired;
        break;
      case ConstraintSetState::Revoked: code = ReasonCode::ConstraintSetRevoked; break;
      case ConstraintSetState::Superseded: code = ReasonCode::ConstraintSetSuperseded; break;
      case ConstraintSetState::Retired: code = ReasonCode::ConstraintSetRetired; break;
      default: break;
    }
    add(code, 0, ConstraintId{}, set.id.value(), set.generation.value(), 0);
  } else if (!(candidate.authority_generation == required.path_authority)) {
    add(ReasonCode::StalePathAuthority, 0, ConstraintId{}, candidate.path.value(),
        required.path_authority.value(), candidate.authority_generation.value());
  } else if (candidate.authority_verdict == PathAuthorityVerdict::Rejected) {
    add(ReasonCode::PathNotLegal, 0, ConstraintId{}, candidate.path.value(), 0, 0);
  } else if (candidate.authority_verdict == PathAuthorityVerdict::NotEvaluated) {
    add(ReasonCode::PathAuthorityNotEvaluated, 0, ConstraintId{}, candidate.path.value(), 0, 0);
  } else {
    const EvidenceFamily families[] = {EvidenceFamily::Topology, EvidenceFamily::LinkState,
                                       EvidenceFamily::Capability, EvidenceFamily::FailureDomain,
                                       EvidenceFamily::Policy, EvidenceFamily::Planner};
    for (const EvidenceFamily family : families) {
      if (!oracle_family_consulted(set, family)) {
        continue;
      }
      const std::uint64_t want = oracle_required(required, family);
      const std::uint64_t have = oracle_bound(candidate.evidence, family);
      if (want == 0) {
        add(ReasonCode::EvidenceNotBound, 0, ConstraintId{}, candidate.path.value(), 0, have);
      } else if (want != have) {
        add(oracle_stale_code(family), 0, ConstraintId{}, candidate.path.value(), want, have);
      }
    }

    if (result.reasons.empty()) {
      for (std::uint32_t ordinal = 0; ordinal < set.constraints.size(); ++ordinal) {
        const Constraint& constraint = set.constraints[ordinal];
        if (constraint.scope != ConstraintScope::Mandatory) {
          continue;
        }
        switch (constraint.kind) {
          case ConstraintKind::MaxHopCount:
            if (static_cast<std::int64_t>(candidate.hop_count) > constraint.bound) {
              add(ReasonCode::MaxHopCountExceeded, ordinal, constraint.id, candidate.path.value(),
                  static_cast<std::uint64_t>(constraint.bound), candidate.hop_count);
            }
            break;
          case ConstraintKind::MaxLatency: {
            const EvidenceFamily family = constraint.latency_source == LatencySource::PlannerCost
                                              ? EvidenceFamily::Planner
                                              : EvidenceFamily::LinkState;
            if (candidate.latency.source != constraint.latency_source) {
              add(ReasonCode::LatencyEvidenceUnavailable, ordinal, constraint.id,
                  candidate.path.value(), static_cast<std::uint64_t>(constraint.latency_source),
                  static_cast<std::uint64_t>(candidate.latency.source));
            } else if (candidate.latency.micros > constraint.bound) {
              add(ReasonCode::MaxLatencyExceeded, ordinal, constraint.id, candidate.path.value(),
                  static_cast<std::uint64_t>(constraint.bound),
                  static_cast<std::uint64_t>(candidate.latency.micros));
            }
            (void)family;
            break;
          }
          case ConstraintKind::MinBandwidthCapability: {
            std::int64_t bottleneck = 0;
            bool have = !candidate.links.empty();
            for (const LinkFact& link : candidate.links) {
              if (link.bandwidth.model == CapabilityModel::None ||
                  !(link.bandwidth.generation == required.capability)) {
                have = false;
                break;
              }
              if (bottleneck == 0 || link.bandwidth.bits_per_second < bottleneck) {
                bottleneck = link.bandwidth.bits_per_second;
              }
            }
            if (!have) {
              add(ReasonCode::BandwidthCapabilityUnavailable, ordinal, constraint.id,
                  candidate.path.value(), static_cast<std::uint64_t>(constraint.bound), 0);
            } else if (bottleneck < constraint.bound) {
              add(ReasonCode::MinBandwidthCapabilityNotMet, ordinal, constraint.id,
                  candidate.path.value(), static_cast<std::uint64_t>(constraint.bound),
                  static_cast<std::uint64_t>(bottleneck));
            }
            break;
          }
          case ConstraintKind::RequiredNode:
            for (const NodeId& node : constraint.nodes) {
              if (!oracle_has_node(candidate, node)) {
                add(ReasonCode::RequiredNodeAbsent, ordinal, constraint.id, node.value(), 0, 0);
              }
            }
            break;
          case ConstraintKind::ForbiddenNode:
            for (const NodeId& node : constraint.nodes) {
              if (oracle_has_node(candidate, node)) {
                add(ReasonCode::ForbiddenNodePresent, ordinal, constraint.id, node.value(), 0, 0);
              }
            }
            break;
          case ConstraintKind::RequiredLink:
            for (const LinkId& link : constraint.links) {
              if (!oracle_has_link(candidate, link)) {
                add(ReasonCode::RequiredLinkAbsent, ordinal, constraint.id, link.value(), 0, 0);
              }
            }
            break;
          case ConstraintKind::ForbiddenLink:
            for (const LinkId& link : constraint.links) {
              if (oracle_has_link(candidate, link)) {
                add(ReasonCode::ForbiddenLinkPresent, ordinal, constraint.id, link.value(), 0, 0);
              }
            }
            break;
          case ConstraintKind::RequiredTier:
          case ConstraintKind::ForbiddenTier: {
            const bool positive = constraint.kind == ConstraintKind::RequiredTier;
            for (const NodeFact& node : candidate.nodes) {
              if (!node.tier.is_valid()) {
                if (positive || constraint.unknown_policy == UnknownPolicy::FailClosed) {
                  add(ReasonCode::TierEvidenceUnavailable, ordinal, constraint.id, node.node.value(),
                      0, 0);
                }
                continue;
              }
              const bool member =
                  std::find(constraint.tiers.begin(), constraint.tiers.end(), node.tier) !=
                  constraint.tiers.end();
              if (positive && !member) {
                add(ReasonCode::RequiredTierNotMet, ordinal, constraint.id, node.node.value(), 0,
                    node.tier.value());
              }
              if (!positive && member) {
                add(ReasonCode::ForbiddenTierPresent, ordinal, constraint.id, node.node.value(), 0,
                    node.tier.value());
              }
            }
            break;
          }
          case ConstraintKind::RequiredSite:
          case ConstraintKind::ForbiddenSite: {
            const bool positive = constraint.kind == ConstraintKind::RequiredSite;
            for (const NodeFact& node : candidate.nodes) {
              if (!node.site.is_valid()) {
                if (positive || constraint.unknown_policy == UnknownPolicy::FailClosed) {
                  add(ReasonCode::SiteEvidenceUnavailable, ordinal, constraint.id, node.node.value(),
                      0, 0);
                }
                continue;
              }
              const bool member =
                  std::find(constraint.sites.begin(), constraint.sites.end(), node.site) !=
                  constraint.sites.end();
              if (positive && !member) {
                add(ReasonCode::RequiredSiteNotMet, ordinal, constraint.id, node.node.value(), 0,
                    node.site.value());
              }
              if (!positive && member) {
                add(ReasonCode::ForbiddenSitePresent, ordinal, constraint.id, node.node.value(), 0,
                    node.site.value());
              }
            }
            break;
          }
          case ConstraintKind::LocalityScope:
            for (const NodeFact& node : candidate.nodes) {
              const LocalityRef* found = nullptr;
              for (const LocalityRef& ref : node.localities) {
                if (ref.kind == constraint.domain_kind) {
                  found = &ref;
                  break;
                }
              }
              if (found == nullptr) {
                add(ReasonCode::LocalityEvidenceUnavailable, ordinal, constraint.id,
                    node.node.value(), constraint.locality_domain.value(), 0);
              } else if (!(found->domain == constraint.locality_domain)) {
                add(ReasonCode::LocalityScopeViolated, ordinal, constraint.id, node.node.value(),
                    constraint.locality_domain.value(), found->domain.value());
              }
            }
            break;
          case ConstraintKind::IsolationClass: {
            for (const OracleEntity& entity : oracle_entities(candidate)) {
              const IsolationAttestation* proof = nullptr;
              for (const IsolationAttestation& ref : *entity.isolation) {
                if (ref.isolation_class == constraint.isolation_class) {
                  proof = &ref;
                  break;
                }
              }
              if (proof == nullptr) {
                if (entity.isolation->empty()) {
                  add(ReasonCode::IsolationEvidenceUnavailable, ordinal, constraint.id,
                      entity.identity, constraint.isolation_class.value(), 0);
                } else {
                  add(ReasonCode::IsolationClassNotProven, ordinal, constraint.id, entity.identity,
                      constraint.isolation_class.value(),
                      entity.isolation->front().isolation_class.value());
                }
              } else if (!(proof->generation == required.failure_domain)) {
                add(ReasonCode::IsolationEvidenceUnavailable, ordinal, constraint.id, entity.identity,
                    required.failure_domain.value(), proof->generation.value());
              }
            }
            break;
          }
          case ConstraintKind::RequiredCapability:
            for (const CapabilityId& wanted : constraint.capabilities) {
              for (const OracleEntity& entity : oracle_entities(candidate)) {
                const int generation = oracle_capability_generation(*entity.capabilities, wanted);
                if (generation < 0) {
                  add(ReasonCode::CapabilityEvidenceUnavailable, ordinal, constraint.id,
                      entity.identity, wanted.value(), 0);
                } else if (static_cast<std::uint64_t>(generation) != required.capability.value()) {
                  add(ReasonCode::CapabilityEvidenceUnavailable, ordinal, constraint.id,
                      entity.identity, required.capability.value(),
                      static_cast<std::uint64_t>(generation));
                }
              }
            }
            break;
          case ConstraintKind::ForbiddenCapability:
            for (const CapabilityId& wanted : constraint.capabilities) {
              for (const OracleEntity& entity : oracle_entities(candidate)) {
                const int generation = oracle_capability_generation(*entity.capabilities, wanted);
                if (generation < 0) {
                  if (constraint.unknown_policy == UnknownPolicy::FailClosed) {
                    add(ReasonCode::CapabilityEvidenceUnavailable, ordinal, constraint.id,
                        entity.identity, wanted.value(), 0);
                  }
                } else if (static_cast<std::uint64_t>(generation) != required.capability.value()) {
                  add(ReasonCode::CapabilityEvidenceUnavailable, ordinal, constraint.id,
                      entity.identity, required.capability.value(),
                      static_cast<std::uint64_t>(generation));
                } else {
                  add(ReasonCode::ForbiddenCapabilityPresent, ordinal, constraint.id, entity.identity,
                      wanted.value(), 0);
                }
              }
            }
            break;
          case ConstraintKind::RequiredFailureDomainRelation:
          case ConstraintKind::ForbiddenFailureDomainRelation: {
            const bool required_relation =
                constraint.kind == ConstraintKind::RequiredFailureDomainRelation;
            std::vector<std::uint64_t> domains;
            std::uint64_t incomplete_entity = 0;
            bool complete = true;
            for (const OracleEntity& entity : oracle_entities(candidate)) {
              const FailureDomainRef* found = nullptr;
              for (const FailureDomainRef& ref : *entity.domains) {
                if (ref.kind == constraint.domain_kind) {
                  found = &ref;
                  break;
                }
              }
              if (found == nullptr) {
                complete = false;
                if (incomplete_entity == 0) {
                  incomplete_entity = entity.identity;
                }
                continue;
              }
              domains.push_back(found->domain.value());
            }
            std::sort(domains.begin(), domains.end());
            domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
            const bool fail_closed = constraint.unknown_policy == UnknownPolicy::FailClosed;
            if (!complete && (required_relation || fail_closed)) {
              add(ReasonCode::FailureDomainEvidenceUnavailable, ordinal, constraint.id,
                  incomplete_entity, 0, 0);
              break;
            }
            if (constraint.domain_relation == DomainRelation::Shared) {
              if (complete && domains.size() == 1) {
                add(ReasonCode::ForbiddenFailureDomainRelationMet, ordinal, constraint.id,
                    static_cast<std::uint64_t>(constraint.domain_kind), 0, domains.front());
              }
            } else if (required_relation) {
              if (static_cast<std::int64_t>(domains.size()) < constraint.bound) {
                add(ReasonCode::RequiredFailureDomainRelationNotMet, ordinal, constraint.id,
                    static_cast<std::uint64_t>(constraint.domain_kind),
                    static_cast<std::uint64_t>(constraint.bound),
                    static_cast<std::uint64_t>(domains.size()));
              }
            } else if (static_cast<std::int64_t>(domains.size()) >= constraint.bound) {
              add(ReasonCode::ForbiddenFailureDomainRelationMet, ordinal, constraint.id,
                  static_cast<std::uint64_t>(constraint.domain_kind),
                  static_cast<std::uint64_t>(constraint.bound),
                  static_cast<std::uint64_t>(domains.size()));
            }
            break;
          }
          case ConstraintKind::AdministrativePolicy:
            for (const PolicyId& wanted : constraint.policies) {
              const PolicyAttestation* found = nullptr;
              for (const PolicyAttestation& ref : candidate.policies) {
                if (ref.policy == wanted) {
                  found = &ref;
                  break;
                }
              }
              if (found == nullptr) {
                add(ReasonCode::AdministrativePolicyNotSatisfied, ordinal, constraint.id,
                    wanted.value(), 0, 0);
              } else if (!(found->generation == required.policy)) {
                add(ReasonCode::PolicyEvidenceUnavailable, ordinal, constraint.id, wanted.value(),
                    required.policy.value(), found->generation.value());
              }
            }
            break;
          case ConstraintKind::Unset:
          default:
            break;
        }
      }
    }
  }

  std::stable_sort(result.reasons.begin(), result.reasons.end(), [](const OracleReason& a,
                                                                    const OracleReason& b) {
    return oracle_compare(a, b) < 0;
  });
  const bool has_preferences =
      std::any_of(set.constraints.begin(), set.constraints.end(),
                  [](const Constraint& constraint) {
                    return constraint.scope == ConstraintScope::Preference;
                  });
  if (result.reasons.empty()) {
    result.primary = ReasonCode::None;
    result.outcome = has_preferences ? Outcome::AdmissibleWithPreferences : Outcome::Admissible;
  } else {
    result.primary = result.reasons.front().code;
    result.outcome = oracle_outcome(result.primary);
  }
  return result;
}

/// Independent ordering oracle: insertion sort on the documented precedence.
[[nodiscard]] std::vector<PathId> oracle_order(const std::vector<CandidatePath>& candidates,
                                               const ConstraintSet& set,
                                               const EvidenceRequirements& required) {
  struct Entry {
    PathId path{};
    bool admissible{false};
    std::vector<PreferenceSlot> preferences{};
    bool has_rank{false};
    std::uint32_t rank{0};
  };
  std::vector<Entry> entries;
  for (const CandidatePath& candidate : candidates) {
    const OracleResult oracle = oracle_evaluate(set, candidate, required);
    Entry entry;
    entry.path = candidate.path;
    entry.admissible = oracle.outcome == Outcome::Admissible ||
                       oracle.outcome == Outcome::AdmissibleWithPreferences;
    entry.has_rank = candidate.has_planner_rank;
    entry.rank = candidate.planner_rank;
    for (std::uint32_t ordinal = 0; ordinal < set.constraints.size(); ++ordinal) {
      const Constraint& constraint = set.constraints[ordinal];
      if (constraint.scope != ConstraintScope::Preference) {
        continue;
      }
      PreferenceSlot slot;
      slot.constraint = constraint.id;
      slot.kind = constraint.kind;
      slot.constraint_ordinal = ordinal;
      slot.rank = constraint.preference_rank;
      slot.weight = constraint.preference_weight;
      if (constraint.kind == ConstraintKind::MaxLatency &&
          candidate.latency.source == constraint.latency_source) {
        slot.satisfied = candidate.latency.micros <= constraint.bound;
        slot.margin = constraint.bound - candidate.latency.micros;
      } else if (constraint.kind == ConstraintKind::MaxHopCount) {
        slot.satisfied = static_cast<std::int64_t>(candidate.hop_count) <= constraint.bound;
        slot.margin = constraint.bound - static_cast<std::int64_t>(candidate.hop_count);
      } else {
        slot.satisfied = true;
        slot.margin = 1;
      }
      entry.preferences.push_back(slot);
    }
    std::stable_sort(entry.preferences.begin(), entry.preferences.end(),
                     [](const PreferenceSlot& a, const PreferenceSlot& b) {
                       if (a.rank != b.rank) return a.rank < b.rank;
                       return a.constraint_ordinal < b.constraint_ordinal;
                     });
    entries.push_back(std::move(entry));
  }
  std::stable_sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
    if (a.admissible != b.admissible) return a.admissible;
    const std::size_t shared =
        a.preferences.size() < b.preferences.size() ? a.preferences.size() : b.preferences.size();
    for (std::size_t index = 0; index < shared; ++index) {
      if (a.preferences[index].satisfied != b.preferences[index].satisfied) {
        return a.preferences[index].satisfied;
      }
      if (a.preferences[index].margin != b.preferences[index].margin) {
        return a.preferences[index].margin > b.preferences[index].margin;
      }
    }
    return a.path < b.path;
  });
  std::vector<PathId> ordered;
  for (const Entry& entry : entries) {
    if (entry.admissible) {
      ordered.push_back(entry.path);
    }
  }
  return ordered;
}

[[nodiscard]] CandidatePath random_path(test::Rng& rng, PathId id, const EvidenceRequirements& evidence,
                                        bool with_capability, bool with_policy, bool with_domains) {
  static const std::uint64_t kNodes[] = {10, 11, 12, 77, 20};
  const std::uint32_t node_count = 2 + rng.below(3);
  PathSpec spec;
  spec.path = id;
  for (std::uint32_t index = 0; index < node_count; ++index) {
    spec.nodes.push_back(nid(kNodes[rng.below(5)]));
  }
  // Reject duplicate nodes: the fixture must describe a simple path.
  for (std::size_t a = 0; a < spec.nodes.size(); ++a) {
    for (std::size_t b = a + 1; b < spec.nodes.size(); ++b) {
      if (spec.nodes[a] == spec.nodes[b]) {
        spec.nodes[b] = nid(200 + b);
      }
    }
  }
  spec.first_link = 1000 + id.value() * 10;
  spec.tier = tid(1 + rng.below(2));
  spec.site = sid(5 + rng.below(2));
  if (rng.coin()) {
    spec.localities.push_back(LocalityRef{DomainKind::Site, locality(700 + rng.below(2))});
  }
  if (with_domains) {
    spec.domains.push_back(FailureDomainRef{DomainKind::Rack, domain(41 + rng.below(2))});
  }
  if (with_capability && rng.coin()) {
    spec.capabilities.push_back(capid(5));
  }
  if (with_capability && rng.coin()) {
    spec.isolation_classes.push_back(isolation_class(3));
  }
  if (with_policy && rng.coin()) {
    spec.policies.push_back(pid(3));
  }
  if (rng.coin()) {
    spec.planner_latency_micros = 1000 + static_cast<std::int64_t>(rng.below(12000));
  } else {
    spec.observed_latency_micros = 1000 + static_cast<std::int64_t>(rng.below(12000));
  }
  if (rng.coin()) {
    spec.bandwidth_bits_per_second = 1000 + static_cast<std::int64_t>(rng.below(2000));
  }
  spec.has_planner_rank = rng.coin();
  spec.planner_rank = rng.below(4);
  const PathAuthorityVerdict verdicts[] = {PathAuthorityVerdict::Legal, PathAuthorityVerdict::Legal,
                                           PathAuthorityVerdict::Legal,
                                           PathAuthorityVerdict::Rejected,
                                           PathAuthorityVerdict::NotEvaluated};
  spec.verdict = verdicts[rng.below(5)];
  if (rng.below(8) == 0) {
    spec.authority_generation = PathAuthorityGeneration::from_value(99);
  }
  return build_candidate(spec, evidence);
}

[[nodiscard]] ConstraintSet random_set(test::Rng& rng, const EvidenceRequirements& evidence) {
  std::vector<Constraint> constraints;
  std::uint64_t id = 1;
  const std::uint32_t count = 1 + rng.below(6);
  static const std::uint64_t kNodes[] = {10, 11, 12, 77, 20};
  static const std::uint64_t kLinks[] = {1000, 1001, 1002, 1010, 1020, 1030};
  for (std::uint32_t index = 0; index < count; ++index, ++id) {
    switch (rng.below(11)) {
      case 0:
        constraints.push_back(max_hops(cid(id), 1 + static_cast<std::int64_t>(rng.below(4))));
        break;
      case 1:
        constraints.push_back(max_latency(cid(id),
                                          rng.coin() ? LatencySource::PlannerCost
                                                     : LatencySource::ObservedLatency,
                                          2000 + static_cast<std::int64_t>(rng.below(9000))));
        break;
      case 2:
        constraints.push_back(min_bandwidth(cid(id), 1000 + static_cast<std::int64_t>(rng.below(1500))));
        break;
      case 3:
        constraints.push_back(with_nodes(cid(id),
                                         rng.coin() ? ConstraintKind::RequiredNode
                                                    : ConstraintKind::ForbiddenNode,
                                         {nid(kNodes[rng.below(5)])}));
        break;
      case 4:
        constraints.push_back(with_links(cid(id),
                                         rng.coin() ? ConstraintKind::RequiredLink
                                                    : ConstraintKind::ForbiddenLink,
                                         {lid(kLinks[rng.below(6)])}));
        break;
      case 5:
        constraints.push_back(with_tiers(cid(id),
                                         rng.coin() ? ConstraintKind::RequiredTier
                                                    : ConstraintKind::ForbiddenTier,
                                         {tid(1 + rng.below(2))}));
        break;
      case 6:
        constraints.push_back(with_sites(cid(id),
                                         rng.coin() ? ConstraintKind::RequiredSite
                                                    : ConstraintKind::ForbiddenSite,
                                         {sid(5 + rng.below(2))}));
        break;
      case 7: {
        Constraint constraint = locality_scope(cid(id), DomainKind::Site, locality(700 + rng.below(2)));
        constraints.push_back(constraint);
        break;
      }
      case 8:
        constraints.push_back(isolation_required(cid(id), isolation_class(3)));
        break;
      case 9:
        constraints.push_back(with_capabilities(cid(id),
                                                rng.coin() ? ConstraintKind::RequiredCapability
                                                           : ConstraintKind::ForbiddenCapability,
                                                {capid(5)}));
        constraints.back().unknown_policy =
            rng.coin() ? UnknownPolicy::FailClosed : UnknownPolicy::PermitUnknownNegative;
        break;
      default:
        constraints.push_back(with_policies(cid(id), {pid(3)}));
        break;
    }
  }
  Constraint preference = max_latency(cid(900), LatencySource::PlannerCost, 10000);
  as_preference(preference, 1, 2);
  const bool wants_preference = rng.coin();
  if (wants_preference) {
    constraints.push_back(preference);
  }
  ConstraintSet set;
  set.id = setid(1);
  set.generation = ConstraintSetGeneration::from_value(1);
  set.state = ConstraintSetState::Active;
  set.constraints = std::move(constraints);
  set.evidence = evidence;
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status = validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
  if (!status.ok()) {
    set.state = ConstraintSetState::Declared;  // marks an unusable random set
    set.name = "unsat";
  }
  return set;
}

}  // namespace

CRF_TEST(Oracle, RandomizedAgreementWithTheProductionEvaluator) {
  const EvidenceRequirements evidence = standard_evidence();
  const std::uint64_t seeds[] = {1, 7, 12345, 0xabcdef, 999983};
  for (const std::uint64_t seed : seeds) {
    test::Rng rng(seed);
    for (int iteration = 0; iteration < 60; ++iteration) {
      ConstraintSet set = random_set(rng, evidence);
      if (set.name == "unsat") {
        continue;
      }
      std::vector<CandidatePath> candidates;
      const std::uint32_t population = 1 + rng.below(5);
      for (std::uint32_t index = 0; index < population; ++index) {
        candidates.push_back(random_path(rng, pathid(100 + index), evidence, true, true, true));
      }
      EvidenceRequirements required = evidence;
      if (rng.below(6) == 0) {
        required.capability = CapabilityGeneration::from_value(6);
      }
      if (rng.below(8) == 0) {
        required.topology = TopologyGeneration::from_value(4);
      }
      const EvaluationContext context = context_for(set, required);
      const Result<EvaluationBatch> batch = evaluate_batch(context, candidates);
      CRF_CHECK_RESULT(batch);
      if (!batch.ok()) {
        continue;
      }
      for (const CandidatePath& candidate : candidates) {
        // The randomized fixture must always describe a structurally valid
        // candidate; a malformed one would make the comparison meaningless.
        CRF_CHECK_STATUS(validate_candidate(candidate, Limits{}));
        CRF_CHECK_STATUS(canonicalize_candidate(const_cast<CandidatePath&>(candidate), Limits{}));
        const Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
        CRF_CHECK_RESULT(record);
        if (!record.ok()) {
          continue;
        }
        const OracleResult oracle = oracle_evaluate(set, candidate, required);
        const std::string context_text = test::seed_message("oracle disagreement", seed) +
                                         " iteration=" + std::to_string(iteration) +
                                         " path=" + std::to_string(candidate.path.value());
        if (record.value().outcome != oracle.outcome) {
          CRF_FAIL(context_text + " outcome production=" + to_string(record.value().outcome) +
                   " oracle=" + to_string(oracle.outcome));
          continue;
        }
        if (record.value().primary_reason != oracle.primary) {
          CRF_FAIL(context_text + " primary production=" +
                   to_string(record.value().primary_reason) + " oracle=" + to_string(oracle.primary));
          continue;
        }
        CRF_CHECK_EQ(record.value().reasons.size(), oracle.reasons.size());
        if (record.value().reasons.size() == oracle.reasons.size()) {
          for (std::size_t index = 0; index < oracle.reasons.size(); ++index) {
            CRF_CHECK_EQ(static_cast<std::uint16_t>(record.value().reasons[index].code),
                         static_cast<std::uint16_t>(oracle.reasons[index].code));
            CRF_CHECK_EQ(record.value().reasons[index].constraint, oracle.reasons[index].constraint);
            CRF_CHECK_EQ(record.value().reasons[index].constraint_ordinal,
                         oracle.reasons[index].ordinal);
            CRF_CHECK_EQ(record.value().reasons[index].subject, oracle.reasons[index].subject);
            CRF_CHECK_EQ(record.value().reasons[index].expected, oracle.reasons[index].expected);
            CRF_CHECK_EQ(record.value().reasons[index].actual, oracle.reasons[index].actual);
          }
        }
      }
      const std::vector<PathId> oracle_ordering = oracle_order(candidates, set, required);
      CRF_CHECK_EQ(batch.value().admissible_order.size(), oracle_ordering.size());
      for (std::size_t index = 0; index < oracle_ordering.size() &&
                                  index < batch.value().admissible_order.size(); ++index) {
        CRF_CHECK_EQ(batch.value().admissible_order[index].path, oracle_ordering[index]);
      }
    }
  }
}

CRF_TEST(Oracle, ForbiddenNodeOrderingPermutations) {
  const EvidenceRequirements evidence = standard_evidence();
  const std::vector<std::uint64_t> node_pool = {10, 11, 12};
  std::vector<NodeId> required;
  for (const std::uint64_t value : node_pool) {
    required.push_back(nid(value));
  }
  const ConstraintSet set = make_set(
      setid(1),
      {with_nodes(cid(1), ConstraintKind::RequiredNode, required),
       with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(77)})},
      evidence);

  // Every permutation of the node list must produce the same digest and the
  // same outcome: a forbidden entity excludes the candidate whatever the
  // declaration order was.
  std::vector<NodeId> permutation = required;
  std::sort(permutation.begin(), permutation.end());
  std::size_t permutations = 0;
  do {
    const ConstraintSet candidate_set = make_set(
        setid(1),
        {with_nodes(cid(1), ConstraintKind::RequiredNode, permutation),
         with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(77)})},
        evidence);
    CRF_CHECK_EQ(candidate_set.digest, set.digest);
    ++permutations;
  } while (std::next_permutation(permutation.begin(), permutation.end()));
  CRF_CHECK_EQ(permutations, std::size_t{6});

  PathSpec with_forbidden;
  with_forbidden.path = pathid(1);
  with_forbidden.nodes = {nid(77), nid(10), nid(11), nid(12)};
  with_forbidden.first_link = 1000;
  const Result<EvaluationRecord> record =
      evaluate_candidate(context_for(set, evidence), build_candidate(with_forbidden, evidence));
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::ForbiddenNodePresent);

  PathSpec clean;
  clean.path = pathid(2);
  clean.nodes = {nid(10), nid(11), nid(12)};
  clean.first_link = 1100;
  const Result<EvaluationRecord> clean_record =
      evaluate_candidate(context_for(set, evidence), build_candidate(clean, evidence));
  CRF_CHECK_RESULT(clean_record);
  CRF_CHECK_EQ(clean_record.value().outcome, Outcome::Admissible);
}

CRF_TEST(Oracle, ContradictionRejectionProof) {
  const EvidenceRequirements evidence = standard_evidence();
  ConstraintSet set;
  set.id = setid(1);
  set.generation = ConstraintSetGeneration::from_value(1);
  set.constraints = {with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(42)}),
                     with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(42)})};
  set.evidence = evidence;
  const Digest256 before = constraint_set_digest(set);
  const std::size_t count_before = set.constraints.size();
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status = validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
  CRF_CHECK_EQ(status.code(), ErrorCode::ContradictoryConstraintSet);
  CRF_CHECK_EQ(contradictions.size(), std::size_t{1});
  CRF_CHECK_EQ(contradictions[0].kind, ContradictionKind::RequiredAndForbiddenSameEntity);
  // Atomic rejection: the caller's set is byte-identical to before the call.
  CRF_CHECK_EQ(set.constraints.size(), count_before);
  CRF_CHECK_EQ(constraint_set_digest(set), before);
}

CRF_TEST(Oracle, UnknownLatencyEvidenceProof) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {max_latency(cid(1), LatencySource::ObservedLatency, 100000)}, evidence);
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11)};
  spec.first_link = 1000;
  // No latency evidence at all: the mandatory requirement is unknown, never a
  // silent pass, even though the bound is enormous.
  const Result<EvaluationRecord> record =
      evaluate_candidate(context_for(set, evidence), build_candidate(spec, evidence));
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::LatencyEvidenceUnavailable);

  const OracleResult oracle = oracle_evaluate(set, build_candidate(spec, evidence), evidence);
  CRF_CHECK_EQ(oracle.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(oracle.primary, ReasonCode::LatencyEvidenceUnavailable);
}

CRF_TEST(Oracle, BandwidthCapabilityVersusReservationProof) {
  const EvidenceRequirements evidence = standard_evidence();
  // The constraint is satisfied by capability evidence alone. No reservation is
  // created, nothing is deducted from any capacity pool, and the admissible
  // result carries no capacity claim.
  const ConstraintSet set = make_set(setid(1), {min_bandwidth(cid(1), 1000)}, evidence);
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11)};
  spec.first_link = 1000;
  spec.bandwidth_bits_per_second = 1000;
  const CandidatePath candidate = build_candidate(spec, evidence);
  const Result<EvaluationRecord> record = evaluate_candidate(context_for(set, evidence), candidate);
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::Admissible);
  // Evaluating the same candidate twice changes nothing observable: there is no
  // reservation state to consume.
  const Result<EvaluationRecord> again = evaluate_candidate(context_for(set, evidence), candidate);
  CRF_CHECK_RESULT(again);
  CRF_CHECK_EQ(again.value().digest, record.value().digest);
}

CRF_TEST(Oracle, LocalitySemanticsProof) {
  const EvidenceRequirements evidence = standard_evidence();
  // Two nodes whose identifiers share a prefix but whose authoritative
  // membership differs must be treated by membership, never by name.
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(700), nid(701)};
  spec.first_link = 1000;
  spec.localities = {LocalityRef{DomainKind::Site, locality(999)}};
  const ConstraintSet set = make_set(
      setid(1), {locality_scope(cid(1), DomainKind::Site, locality(700))}, evidence);
  const Result<EvaluationRecord> record =
      evaluate_candidate(context_for(set, evidence), build_candidate(spec, evidence));
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::LocalityScopeViolated);
}
