// Constraint Routing Fabric -- executable public-API examples.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Ten named scenarios. Each one drives the real public entry points of the
// library -- the pure evaluator, the deterministic admissible ordering, the
// atomic constraint-set finalizer and the durable coordinator -- and asserts
// the exact documented behaviour. Nothing here reimplements library logic.
//
// Every figure in this file is SYNTHETIC: it is fabricated to exercise the API
// and is labelled ::crf::EvidenceProvenance::SyntheticFixture. It is not
// telemetry from a real fabric and it is not a statement about any network.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/coordinator.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/evaluator.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/lifecycle.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/ordering.hpp"
#include "constraint_routing_fabric/persistence.hpp"
#include "constraint_routing_fabric/status.hpp"
#include "constraint_routing_fabric/time.hpp"

namespace {

// ---------------------------------------------------------------------------
// Local assertion helper. A failing expectation prints one FAIL line and the
// scenario keeps running, so a single run reports every violation it found.
// ---------------------------------------------------------------------------

class Checks {
 public:
  explicit Checks(std::string scenario) : scenario_(std::move(scenario)) {}

  void expect(bool condition, const std::string& what) {
    ++checks_;
    if (!condition) {
      ++failures_;
      std::cout << "FAIL " << scenario_ << ": " << what << '\n';
    }
  }

  void expect_ok(const crf::Status& status, const std::string& what) {
    expect(status.ok(), what + " [actual=" + std::string(crf::to_string(status.code())) + " " +
                            status.detail() + "]");
  }

  template <class T>
  void expect_ok(const crf::Result<T>& result, const std::string& what) {
    expect(result.ok(), what + " [actual=" + std::string(crf::to_string(result.code())) + " " +
                             result.detail() + "]");
  }

  [[nodiscard]] const char* status() const noexcept { return failures_ == 0 ? "PASS" : "FAIL"; }
  [[nodiscard]] int failures() const noexcept { return failures_; }
  [[nodiscard]] std::size_t checks() const noexcept { return checks_; }

 private:
  std::string scenario_;
  int failures_{0};
  std::size_t checks_{0};
};

/// The one deterministic line every scenario ends with.
void report(const Checks& checks, const std::string& detail) {
  std::cout << checks.status() << ' ' << detail << '\n';
}

/// Mandated explicit statement, printed beside the scenario it belongs to.
void statement(const char* scenario, const std::string& text) {
  std::cout << scenario << " statement: " << text << '\n';
}

[[nodiscard]] std::string code_text(crf::ErrorCode code) { return crf::to_string(code); }
[[nodiscard]] std::string outcome_text(crf::Outcome outcome) { return crf::to_string(outcome); }
[[nodiscard]] std::string reason_text(crf::ReasonCode code) { return crf::to_string(code); }

[[nodiscard]] std::string verdict_text(const crf::EvaluationRecord& record) {
  return outcome_text(record.outcome) + "/" + reason_text(record.primary_reason);
}

// ---------------------------------------------------------------------------
// Synthetic fixture. All identities, generations and evidence values below are
// fabricated here and are labelled as synthetic provenance.
// ---------------------------------------------------------------------------

constexpr crf::Limits kLimits{};

[[nodiscard]] crf::ConstraintSetId set_id(std::uint64_t value) {
  return crf::ConstraintSetId::from_value(value);
}
[[nodiscard]] crf::ConstraintId constraint_id(std::uint64_t value) {
  return crf::ConstraintId::from_value(value);
}
[[nodiscard]] crf::PathId path_id(std::uint64_t value) { return crf::PathId::from_value(value); }
[[nodiscard]] crf::NodeId node_id(std::uint64_t value) { return crf::NodeId::from_value(value); }
[[nodiscard]] crf::SiteId site_id(std::uint64_t value) { return crf::SiteId::from_value(value); }
[[nodiscard]] crf::CapabilityId capability_id(std::uint64_t value) {
  return crf::CapabilityId::from_value(value);
}
[[nodiscard]] crf::PolicyId policy_id(std::uint64_t value) { return crf::PolicyId::from_value(value); }
[[nodiscard]] crf::LocalityDomainId locality_domain(std::uint64_t value) {
  return crf::LocalityDomainId::from_value(value);
}
[[nodiscard]] crf::PublisherId publisher_id(std::uint64_t value) {
  return crf::PublisherId::from_value(value);
}
[[nodiscard]] crf::WorkerBootId worker_boot(std::uint64_t value) {
  return crf::WorkerBootId::from_value(value);
}
[[nodiscard]] crf::SessionId session_id(std::uint64_t value) {
  return crf::SessionId::from_value(value);
}
[[nodiscard]] crf::EvaluationGeneration evaluation_generation(std::uint64_t value) {
  return crf::EvaluationGeneration::from_value(value);
}

/// The authoritative evidence generations the whole fixture binds.
[[nodiscard]] crf::EvidenceRequirements fixture_evidence() {
  crf::EvidenceRequirements evidence;
  evidence.topology = crf::TopologyGeneration::from_value(3);
  evidence.link_state = crf::LinkStateGeneration::from_value(4);
  evidence.capability = crf::CapabilityGeneration::from_value(5);
  evidence.failure_domain = crf::FailureDomainGeneration::from_value(6);
  evidence.policy = crf::PolicyGeneration::from_value(7);
  evidence.planner = crf::PlannerGeneration::from_value(8);
  evidence.path_authority = crf::PathAuthorityGeneration::from_value(9);
  evidence.max_evidence_age_ticks = 0;
  return evidence;
}

[[nodiscard]] crf::EvidenceGenerationSet evidence_binding(const crf::EvidenceRequirements& evidence) {
  crf::EvidenceGenerationSet binding;
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

[[nodiscard]] crf::Constraint typed_constraint(crf::ConstraintId id, crf::ConstraintKind kind) {
  crf::Constraint constraint;
  constraint.id = id;
  constraint.generation = crf::ConstraintGeneration::from_value(1);
  constraint.kind = kind;
  constraint.scope = crf::ConstraintScope::Mandatory;
  return constraint;
}

[[nodiscard]] crf::Constraint max_latency(crf::ConstraintId id, crf::LatencySource source,
                                          std::int64_t micros) {
  crf::Constraint constraint = typed_constraint(id, crf::ConstraintKind::MaxLatency);
  constraint.latency_source = source;
  constraint.bound = micros;
  return constraint;
}

[[nodiscard]] crf::Constraint min_bandwidth(crf::ConstraintId id, std::int64_t bits_per_second) {
  crf::Constraint constraint = typed_constraint(id, crf::ConstraintKind::MinBandwidthCapability);
  constraint.bound = bits_per_second;
  return constraint;
}

[[nodiscard]] crf::Constraint node_constraint(crf::ConstraintId id, crf::ConstraintKind kind,
                                              std::vector<crf::NodeId> nodes) {
  crf::Constraint constraint = typed_constraint(id, kind);
  constraint.nodes = std::move(nodes);
  return constraint;
}

[[nodiscard]] crf::Constraint locality_scope(crf::ConstraintId id, crf::LocalityDomainId domain) {
  crf::Constraint constraint = typed_constraint(id, crf::ConstraintKind::LocalityScope);
  constraint.domain_kind = crf::DomainKind::Site;
  constraint.locality_domain = domain;
  return constraint;
}

[[nodiscard]] crf::Constraint capability_constraint(crf::ConstraintId id, crf::ConstraintKind kind,
                                                    crf::CapabilityId capability) {
  crf::Constraint constraint = typed_constraint(id, kind);
  constraint.capabilities.push_back(capability);
  return constraint;
}

[[nodiscard]] crf::Constraint administrative_policy(crf::ConstraintId id, crf::PolicyId policy) {
  crf::Constraint constraint = typed_constraint(id, crf::ConstraintKind::AdministrativePolicy);
  constraint.policies.push_back(policy);
  return constraint;
}

/// Preference constraints may only order candidates that are already
/// admissible; they can never rescue a hard failure.
[[nodiscard]] crf::Constraint as_preference(crf::Constraint constraint, std::uint32_t rank,
                                            std::uint32_t weight) {
  constraint.scope = crf::ConstraintScope::Preference;
  constraint.preference_rank = rank;
  constraint.preference_weight = weight;
  return constraint;
}

// --- candidate factories ----------------------------------------------------

[[nodiscard]] crf::CandidatePath candidate_path(const crf::EvidenceRequirements& evidence,
                                                crf::PathId path, std::vector<crf::NodeId> nodes) {
  crf::CandidatePath candidate;
  candidate.path = path;
  candidate.authority_generation = evidence.path_authority;
  candidate.authority_verdict = crf::PathAuthorityVerdict::Legal;
  candidate.planner_generation = evidence.planner;
  candidate.evidence = evidence_binding(evidence);
  for (const crf::NodeId& node : nodes) {
    crf::NodeFact fact;
    fact.node = node;
    candidate.nodes.push_back(fact);
  }
  for (std::size_t index = 0; index + 1 < nodes.size(); ++index) {
    crf::LinkFact link;
    link.link = crf::LinkId::from_value(1000 + index);
    link.endpoints[0] = nodes[index];
    link.endpoints[1] = nodes[index + 1];
    link.bandwidth.provenance = crf::EvidenceProvenance::SyntheticFixture;
    candidate.links.push_back(link);
  }
  candidate.hop_count = static_cast<std::uint32_t>(candidate.links.size());
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_planner_latency(crf::CandidatePath candidate,
                                                      std::int64_t micros,
                                                      crf::PlannerGeneration generation) {
  candidate.latency.source = crf::LatencySource::PlannerCost;
  candidate.latency.provenance = crf::EvidenceProvenance::SyntheticFixture;
  candidate.latency.micros = micros;
  candidate.latency.planner_generation = generation;
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_observed_latency(crf::CandidatePath candidate,
                                                       std::int64_t micros,
                                                       crf::LinkStateGeneration generation) {
  candidate.latency.source = crf::LatencySource::ObservedLatency;
  candidate.latency.provenance = crf::EvidenceProvenance::SyntheticFixture;
  candidate.latency.micros = micros;
  candidate.latency.observed_generation = generation;
  candidate.latency.observed_tick = 100;
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_locality(crf::CandidatePath candidate, crf::DomainKind kind,
                                               crf::LocalityDomainId domain) {
  for (crf::NodeFact& node : candidate.nodes) {
    node.localities.push_back(crf::LocalityRef{kind, domain});
  }
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_site_field(crf::CandidatePath candidate, crf::SiteId site) {
  for (crf::NodeFact& node : candidate.nodes) {
    node.site = site;
  }
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_capability(crf::CandidatePath candidate,
                                                 crf::CapabilityId capability,
                                                 crf::CapabilityGeneration generation) {
  for (crf::NodeFact& node : candidate.nodes) {
    node.capabilities.push_back(crf::CapabilityRef{capability, generation});
  }
  for (crf::LinkFact& link : candidate.links) {
    link.capabilities.push_back(crf::CapabilityRef{capability, generation});
  }
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_capability_on_nodes(crf::CandidatePath candidate,
                                                          crf::CapabilityId capability,
                                                          crf::CapabilityGeneration generation) {
  for (crf::NodeFact& node : candidate.nodes) {
    node.capabilities.push_back(crf::CapabilityRef{capability, generation});
  }
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_link_bandwidth(crf::CandidatePath candidate,
                                                     std::size_t link_index,
                                                     std::int64_t bits_per_second,
                                                     crf::CapabilityGeneration generation) {
  crf::LinkFact& link = candidate.links[link_index];
  link.bandwidth.model = crf::CapabilityModel::DeclaredCapabilityRegistry;
  link.bandwidth.provenance = crf::EvidenceProvenance::SyntheticFixture;
  link.bandwidth.bits_per_second = bits_per_second;
  link.bandwidth.generation = generation;
  link.bandwidth.observed_tick = 100;
  return candidate;
}

[[nodiscard]] crf::CandidatePath with_policy(crf::CandidatePath candidate, crf::PolicyId policy,
                                             crf::PolicyGeneration generation) {
  candidate.policies.push_back(crf::PolicyAttestation{policy, generation});
  return candidate;
}

/// Canonicalizes and structurally validates a synthetic candidate, then reports
/// a broken fixture instead of letting a scenario assert against garbage.
[[nodiscard]] crf::CandidatePath finalized_candidate(Checks& checks, crf::CandidatePath candidate) {
  const crf::Status status = crf::canonicalize_candidate(candidate, kLimits);
  checks.expect_ok(status, "the synthetic fixture candidate is well formed");
  return candidate;
}

/// Finalizes a canonical constraint set through the real public entry point, so
/// every scenario starts from a set the runtime itself accepted.
[[nodiscard]] crf::ConstraintSet finalized_set(Checks& checks, crf::ConstraintSetId id,
                                               std::vector<crf::Constraint> constraints,
                                               const crf::EvidenceRequirements& evidence,
                                               crf::RankingPolicy ranking = {}) {
  crf::ConstraintSet set;
  set.id = id;
  set.generation = crf::ConstraintSetGeneration::from_value(1);
  set.state = crf::ConstraintSetState::Active;
  set.name = "crf-examples-synthetic";
  set.constraints = std::move(constraints);
  set.evidence = evidence;
  set.ranking = ranking;
  std::vector<crf::SetDefect> defects;
  std::vector<crf::Contradiction> contradictions;
  const crf::Status status =
      crf::validate_and_finalize_constraint_set(set, kLimits, defects, contradictions);
  checks.expect_ok(status, "the synthetic fixture constraint set is canonical and contradiction free");
  return set;
}

// --- evaluation helpers -----------------------------------------------------

[[nodiscard]] crf::EvaluationContext evaluation_context(const crf::ConstraintSet& set,
                                                        const crf::EvidenceRequirements& evidence,
                                                        crf::EvaluationGeneration generation) {
  crf::EvaluationContext context;
  context.set = &set;
  context.current = evidence;
  context.limits = &kLimits;
  context.now_tick = 1000;
  context.generation = generation;
  context.provenance.epoch = crf::CoordinatorEpoch::from_value(1);
  context.provenance.publisher = publisher_id(1);
  context.provenance.worker_boot = worker_boot(1);
  context.provenance.attempt = crf::MutationAttemptId::from_value(1);
  context.provenance.request = crf::RequestId::from_value(1);
  // These scenarios call the pure evaluator directly. The coordinator sets this
  // flag itself once it has authorized the caller against the live registry.
  context.authority_verified = true;
  return context;
}

[[nodiscard]] crf::EvaluationRecord evaluate_checked(Checks& checks, const crf::ConstraintSet& set,
                                                     const crf::EvidenceRequirements& evidence,
                                                     const crf::CandidatePath& candidate,
                                                     crf::EvaluationGeneration generation) {
  const crf::EvaluationContext context = evaluation_context(set, evidence, generation);
  const crf::Result<crf::EvaluationRecord> result = crf::evaluate_candidate(context, candidate);
  checks.expect_ok(result, "evaluate_candidate() succeeds for synthetic path " +
                               crf::to_string(candidate.path));
  return result.ok() ? result.value() : crf::EvaluationRecord{};
}

[[nodiscard]] crf::EvaluationBatch evaluate_population_checked(
    Checks& checks, const crf::ConstraintSet& set, const crf::EvidenceRequirements& evidence,
    std::span<const crf::CandidatePath> population, crf::EvaluationGeneration generation) {
  const crf::EvaluationContext context = evaluation_context(set, evidence, generation);
  const crf::Result<crf::EvaluationBatch> result = crf::evaluate_batch(context, population);
  checks.expect_ok(result, "evaluate_batch() succeeds for the synthetic population");
  return result.ok() ? result.value() : crf::EvaluationBatch{};
}

[[nodiscard]] const crf::EvaluationRecord* record_for(const crf::EvaluationBatch& batch,
                                                      crf::PathId path) {
  for (const crf::EvaluationRecord& record : batch.records) {
    if (record.path == path) {
      return &record;
    }
  }
  return nullptr;
}

[[nodiscard]] const crf::Reason* reason_of(const crf::EvaluationRecord& record,
                                           crf::ReasonCode code) {
  for (const crf::Reason& reason : record.reasons) {
    if (reason.code == code) {
      return &reason;
    }
  }
  return nullptr;
}

[[nodiscard]] bool contains_path(std::span<const crf::RankedCandidate> order, crf::PathId path) {
  for (const crf::RankedCandidate& ranked : order) {
    if (ranked.path == path) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool has_cause(const crf::CurrentnessReport& report, crf::CurrentnessCause cause) {
  for (const crf::CurrentnessCause value : report.causes) {
    if (value == cause) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] std::string cause_text(const crf::CurrentnessReport& report) {
  std::string text;
  for (const crf::CurrentnessCause cause : report.causes) {
    if (!text.empty()) {
      text += "+";
    }
    text += crf::to_string(cause);
  }
  return text.empty() ? std::string("None") : text;
}

// --- coordinator helpers ----------------------------------------------------

[[nodiscard]] constexpr crf::AuthorityScopeMask publisher_scopes() noexcept {
  return crf::scope_bit(crf::AuthorityScope::PublishConstraintSet) |
         crf::scope_bit(crf::AuthorityScope::PublishEvaluation) |
         crf::scope_bit(crf::AuthorityScope::ApplyLifecycle) |
         crf::scope_bit(crf::AuthorityScope::ReadDefinitions) |
         crf::scope_bit(crf::AuthorityScope::ReadResults) |
         crf::scope_bit(crf::AuthorityScope::AdministerFencing);
}

/// Hands out fresh mutation-attempt and request identities. A reused attempt
/// identity is a conflict by contract, so scenarios never guess one.
class AttemptSequencer {
 public:
  explicit AttemptSequencer(crf::CoordinatorEpoch epoch) : epoch_(epoch) {}

  [[nodiscard]] crf::AuthorityContext next(crf::PublisherId publisher, crf::WorkerBootId boot,
                                           crf::SessionId session,
                                           crf::AuthorityScopeMask scopes) {
    crf::AuthorityContext context;
    context.epoch = epoch_;
    context.publisher = publisher;
    context.worker_boot = boot;
    context.attempt = crf::MutationAttemptId::from_value(next_identity_++);
    context.request = crf::RequestId::from_value(next_identity_);
    context.session = session;
    context.scopes = scopes;
    return context;
  }

 private:
  crf::CoordinatorEpoch epoch_;
  std::uint64_t next_identity_{1};
};

[[nodiscard]] crf::CoordinatorConfig coordinator_config(const crf::EvidenceRequirements& evidence) {
  crf::CoordinatorConfig config;
  config.limits = crf::Limits{};
  config.evidence = evidence;
  config.allow_initialize = true;
  config.grants.push_back(crf::PublisherGrant{publisher_id(1), publisher_scopes()});
  return config;
}

/// A definition every coordinator scenario can publish, activate and evaluate:
/// one positive capability requirement.
[[nodiscard]] crf::ConstraintSet required_capability_definition(
    Checks& checks, const crf::EvidenceRequirements& evidence, crf::ConstraintSetId id,
    crf::CapabilityId capability) {
  return finalized_set(
      checks, id,
      {capability_constraint(constraint_id(90), crf::ConstraintKind::RequiredCapability, capability)},
      evidence);
}

// ---------------------------------------------------------------------------
// 1. latency_bound
// ---------------------------------------------------------------------------

void run_latency_bound(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::ConstraintSet set = finalized_set(
      checks, set_id(101),
      {max_latency(constraint_id(1), crf::LatencySource::PlannerCost, 2500)}, evidence);

  const crf::CandidatePath inside = finalized_candidate(
      checks, with_planner_latency(
                  candidate_path(evidence, path_id(1), {node_id(11), node_id(12)}), 2000,
                  evidence.planner));
  const crf::CandidatePath outside = finalized_candidate(
      checks, with_planner_latency(
                  candidate_path(evidence, path_id(2), {node_id(13), node_id(14)}), 4000,
                  evidence.planner));
  // Well inside the numeric bound, but measured instead of modelled.
  const crf::CandidatePath observed_only = finalized_candidate(
      checks, with_observed_latency(
                  candidate_path(evidence, path_id(3), {node_id(15), node_id(16)}), 1000,
                  evidence.link_state));

  const crf::EvaluationRecord inside_record =
      evaluate_checked(checks, set, evidence, inside, evaluation_generation(1));
  const crf::EvaluationRecord outside_record =
      evaluate_checked(checks, set, evidence, outside, evaluation_generation(2));
  const crf::EvaluationRecord observed_record =
      evaluate_checked(checks, set, evidence, observed_only, evaluation_generation(3));

  checks.expect(inside_record.outcome == crf::Outcome::Admissible,
                "a candidate inside the planner-cost bound is ADMISSIBLE [actual=" +
                    verdict_text(inside_record) + "]");
  checks.expect(outside_record.outcome == crf::Outcome::HardConstraintFailed,
                "a candidate outside the bound is HARD_CONSTRAINT_FAILED [actual=" +
                    verdict_text(outside_record) + "]");
  checks.expect(outside_record.primary_reason == crf::ReasonCode::MaxLatencyExceeded,
                "the primary reason outside the bound is MAX_LATENCY_EXCEEDED [actual=" +
                    reason_text(outside_record.primary_reason) + "]");
  checks.expect(observed_record.outcome == crf::Outcome::UnknownRequiredEvidence,
                "observed-only latency cannot satisfy a planner-cost bound [actual=" +
                    verdict_text(observed_record) + "]");
  checks.expect(observed_record.primary_reason == crf::ReasonCode::LatencyEvidenceUnavailable,
                "the primary reason for the wrong evidence model is "
                "LATENCY_EVIDENCE_UNAVAILABLE [actual=" +
                    reason_text(observed_record.primary_reason) + "]");
  checks.expect(observed_only.latency.micros <= 2500,
                "the observed figure is numerically inside the bound, so only the evidence model "
                "can be the reason it is rejected");

  const crf::Reason* mismatch =
      reason_of(observed_record, crf::ReasonCode::LatencyEvidenceUnavailable);
  checks.expect(mismatch != nullptr &&
                    mismatch->expected == static_cast<std::uint64_t>(crf::LatencySource::PlannerCost) &&
                    mismatch->actual == static_cast<std::uint64_t>(crf::LatencySource::ObservedLatency),
                "the reason names the required model and the supplied model, so modelled and "
                "measured latency are never mixed");

  report(checks,
         std::string("latency_bound: ") + checks.status() +
             " [planner-2000us(bound 2500us)=" + verdict_text(inside_record) +
             "; planner-4000us=" + verdict_text(outside_record) + "; observed-1000us=" +
             verdict_text(observed_record) + " expected-model=" +
             crf::to_string(crf::LatencySource::PlannerCost) + " actual-model=" +
             crf::to_string(crf::LatencySource::ObservedLatency) + "]");
}

// ---------------------------------------------------------------------------
// 2. bandwidth_capability
// ---------------------------------------------------------------------------

void run_bandwidth_capability(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  constexpr std::int64_t kThreshold = 1000000000;
  const crf::ConstraintSet set = finalized_set(
      checks, set_id(201), {min_bandwidth(constraint_id(2), kThreshold)}, evidence);

  const crf::CandidatePath meeting = finalized_candidate(
      checks,
      with_link_bandwidth(
          with_link_bandwidth(
              candidate_path(evidence, path_id(21), {node_id(21), node_id(22), node_id(23)}), 0,
              4000000000, evidence.capability),
          1, kThreshold, evidence.capability));
  const crf::CandidatePath below = finalized_candidate(
      checks,
      with_link_bandwidth(
          with_link_bandwidth(
              candidate_path(evidence, path_id(22), {node_id(24), node_id(25), node_id(26)}), 0,
              kThreshold, evidence.capability),
          1, 250000000, evidence.capability));
  const crf::CandidatePath unattested = finalized_candidate(
      checks, candidate_path(evidence, path_id(23), {node_id(27), node_id(28)}));

  std::int64_t bottleneck = 0;
  const bool attested = crf::path_bandwidth_capability(meeting, evidence.capability, bottleneck);
  checks.expect(attested && bottleneck == kThreshold,
                "the path bottleneck is the lowest attested link capability (expected " +
                    std::to_string(kThreshold) + ", actual " + std::to_string(bottleneck) + ")");
  std::int64_t unattested_bottleneck = 0;
  checks.expect(!crf::path_bandwidth_capability(unattested, evidence.capability,
                                                unattested_bottleneck),
                "a path whose links carry no capability evidence has no bottleneck figure");

  const crf::EvaluationRecord meeting_record =
      evaluate_checked(checks, set, evidence, meeting, evaluation_generation(1));
  const crf::EvaluationRecord below_record =
      evaluate_checked(checks, set, evidence, below, evaluation_generation(2));
  const crf::EvaluationRecord unattested_record =
      evaluate_checked(checks, set, evidence, unattested, evaluation_generation(3));

  checks.expect(meeting_record.outcome == crf::Outcome::Admissible,
                "a path whose bottleneck meets the threshold passes [actual=" +
                    verdict_text(meeting_record) + "]");
  checks.expect(below_record.outcome == crf::Outcome::HardConstraintFailed &&
                    below_record.primary_reason ==
                        crf::ReasonCode::MinBandwidthCapabilityNotMet,
                "a path below the threshold fails MIN_BANDWIDTH_CAPABILITY_NOT_MET [actual=" +
                    verdict_text(below_record) + "]");
  checks.expect(unattested_record.outcome == crf::Outcome::UnknownRequiredEvidence &&
                    unattested_record.primary_reason ==
                        crf::ReasonCode::BandwidthCapabilityUnavailable,
                "links with no capability evidence at the required generation are "
                "UNKNOWN_REQUIRED_EVIDENCE/BANDWIDTH_CAPABILITY_UNAVAILABLE [actual=" +
                    verdict_text(unattested_record) + "]");

  statement("bandwidth_capability",
            "MinBandwidthCapability compares attestED capability evidence only: it reserves no "
            "bandwidth and guarantees no delivered throughput.");

  report(checks,
         std::string("bandwidth_capability: ") + checks.status() + " [threshold=" +
             std::to_string(kThreshold) + "bps bottleneck=" + std::to_string(bottleneck) +
             " -> " + verdict_text(meeting_record) + "; 250000000bps -> " +
             verdict_text(below_record) + "; no-capability-evidence -> " +
             verdict_text(unattested_record) + "]");
}

// ---------------------------------------------------------------------------
// 3. forbidden_topology_entity
// ---------------------------------------------------------------------------

void run_forbidden_topology_entity(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::NodeId excluded = node_id(31);

  const crf::Constraint forbidden =
      node_constraint(constraint_id(3), crf::ConstraintKind::ForbiddenNode, {excluded});
  const crf::Constraint preference =
      as_preference(max_latency(constraint_id(4), crf::LatencySource::PlannerCost, 10000), 1, 1000);

  const crf::ConstraintSet guarded =
      finalized_set(checks, set_id(301), {forbidden, preference}, evidence);
  const crf::ConstraintSet preference_only =
      finalized_set(checks, set_id(302), {preference}, evidence);

  const crf::CandidatePath crossing = finalized_candidate(
      checks, with_planner_latency(
                  candidate_path(evidence, path_id(31), {node_id(30), excluded, node_id(32)}), 500,
                  evidence.planner));
  const crf::CandidatePath avoiding = finalized_candidate(
      checks, with_planner_latency(
                  candidate_path(evidence, path_id(32), {node_id(33), node_id(34), node_id(35)}),
                  500, evidence.planner));

  const std::vector<crf::CandidatePath> population{crossing, avoiding};
  const crf::EvaluationBatch guarded_batch =
      evaluate_population_checked(checks, guarded, evidence, population, evaluation_generation(1));

  const crf::EvaluationRecord* crossing_record = record_for(guarded_batch, crossing.path);
  const crf::EvaluationRecord* avoiding_record = record_for(guarded_batch, avoiding.path);
  checks.expect(crossing_record != nullptr && avoiding_record != nullptr,
                "the batch contains one record per synthetic candidate");
  if (crossing_record == nullptr || avoiding_record == nullptr) {
    report(checks, std::string("forbidden_topology_entity: ") + checks.status() +
                       " [batch did not produce the expected records]");
    return;
  }

  checks.expect(crossing_record->outcome == crf::Outcome::HardConstraintFailed &&
                    crossing_record->primary_reason == crf::ReasonCode::ForbiddenNodePresent,
                "a path traversing the forbidden node is HARD_CONSTRAINT_FAILED/"
                "FORBIDDEN_NODE_PRESENT [actual=" + verdict_text(*crossing_record) + "]");
  checks.expect(avoiding_record->outcome == crf::Outcome::AdmissibleWithPreferences,
                "the path that avoids it is admissible and carries preferences [actual=" +
                    verdict_text(*avoiding_record) + "]");
  checks.expect(crossing_record->preferences.empty(),
                "the preference is never even evaluated for a hard failure (preference vector "
                "size " + std::to_string(crossing_record->preferences.size()) + ")");
  checks.expect(guarded_batch.admissible_order.size() == 1 &&
                    contains_path(guarded_batch.admissible_order, avoiding.path),
                "the admissible ordering contains exactly the non-traversing candidate");
  checks.expect(!contains_path(guarded_batch.admissible_order, crossing.path),
                "the excluded candidate never appears in the admissible ordering");
  checks.expect(guarded_batch.batch_outcome == crf::BatchOutcome::AdmissibleCandidatesAvailable,
                "the batch still reports admissible candidates available");

  // Control: with the hard exclusion removed, that same candidate satisfies the
  // very preference that was supposed to be its rescue.
  const crf::EvaluationRecord control =
      evaluate_checked(checks, preference_only, evidence, crossing, evaluation_generation(2));
  checks.expect(control.outcome == crf::Outcome::AdmissibleWithPreferences &&
                    control.preferences.size() == 1 && control.preferences.front().satisfied &&
                    control.preferences.front().weight == 1000,
                "without the exclusion the same candidate satisfies the weight-1000 preference, "
                "so the preference could never have rescued it [actual=" + verdict_text(control) +
                    "]");

  report(checks,
         std::string("forbidden_topology_entity: ") + checks.status() + " [traversing node " +
             std::to_string(excluded.value()) + " -> " + verdict_text(*crossing_record) +
             ", preferences=" + std::to_string(crossing_record->preferences.size()) +
             "; avoiding -> " + verdict_text(*avoiding_record) + "; admissible_order=" +
             std::to_string(guarded_batch.admissible_order.size()) +
             "; preference-only control -> " + verdict_text(control) + "]");
}

// ---------------------------------------------------------------------------
// 4. locality
// ---------------------------------------------------------------------------

void run_locality(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::LocalityDomainId authoritative = locality_domain(41);
  const crf::LocalityDomainId other = locality_domain(42);
  const crf::ConstraintSet set = finalized_set(
      checks, set_id(401), {locality_scope(constraint_id(5), authoritative)}, evidence);

  const crf::CandidatePath member = finalized_candidate(
      checks, with_locality(candidate_path(evidence, path_id(41), {node_id(41), node_id(42)}),
                            crf::DomainKind::Site, authoritative));
  const crf::CandidatePath foreign = finalized_candidate(
      checks, with_site_field(
                  with_locality(
                      candidate_path(evidence, path_id(42), {node_id(43), node_id(44)}),
                      crf::DomainKind::Site, other),
                  site_id(41)));
  const crf::CandidatePath unattested = finalized_candidate(
      checks, candidate_path(evidence, path_id(43), {node_id(45), node_id(46)}));

  const crf::EvaluationRecord member_record =
      evaluate_checked(checks, set, evidence, member, evaluation_generation(1));
  const crf::EvaluationRecord foreign_record =
      evaluate_checked(checks, set, evidence, foreign, evaluation_generation(2));
  const crf::EvaluationRecord unattested_record =
      evaluate_checked(checks, set, evidence, unattested, evaluation_generation(3));

  checks.expect(!member.nodes.front().site.is_valid(),
                "the accepted candidate carries no site field at all, so membership was read "
                "from its authoritative locality reference");
  checks.expect(member_record.outcome == crf::Outcome::Admissible,
                "a candidate whose nodes carry the authoritative site membership passes [actual=" +
                    verdict_text(member_record) + "]");
  checks.expect(foreign_record.outcome == crf::Outcome::HardConstraintFailed &&
                    foreign_record.primary_reason == crf::ReasonCode::LocalityScopeViolated,
                "a candidate whose nodes carry a different authoritative site fails "
                "LOCALITY_SCOPE_VIOLATED [actual=" + verdict_text(foreign_record) + "]");
  const crf::Reason* violated = reason_of(foreign_record, crf::ReasonCode::LocalityScopeViolated);
  checks.expect(violated != nullptr && violated->expected == authoritative.value() &&
                    violated->actual == other.value(),
                "the violation names the required and the observed authoritative identities");
  checks.expect(unattested_record.outcome == crf::Outcome::UnknownRequiredEvidence &&
                    unattested_record.primary_reason ==
                        crf::ReasonCode::LocalityEvidenceUnavailable,
                "nodes with no site membership at all are UNKNOWN_REQUIRED_EVIDENCE/"
                "LOCALITY_EVIDENCE_UNAVAILABLE [actual=" + verdict_text(unattested_record) + "]");

  statement("locality",
            "LocalityScope is read from authoritative LocalityRef membership identities; it is "
            "never derived from a name prefix or from any name-shaped field.");

  report(checks,
         std::string("locality: ") + checks.status() + " [site " +
             std::to_string(authoritative.value()) + " membership -> " +
             verdict_text(member_record) + "; site " + std::to_string(other.value()) + " -> " +
             verdict_text(foreign_record) + "; no membership -> " +
             verdict_text(unattested_record) + "]");
}

// ---------------------------------------------------------------------------
// 5. capability_requirement
// ---------------------------------------------------------------------------

void run_capability_requirement(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::CapabilityId required_capability = capability_id(51);
  const crf::CapabilityId forbidden_capability = capability_id(52);

  const crf::Constraint required = capability_constraint(
      constraint_id(6), crf::ConstraintKind::RequiredCapability, required_capability);
  crf::Constraint forbidden = capability_constraint(
      constraint_id(7), crf::ConstraintKind::ForbiddenCapability, forbidden_capability);
  // A negative constraint is satisfied by the absence of the capability only
  // when the operator says so explicitly; the default is fail-closed.
  forbidden.unknown_policy = crf::UnknownPolicy::PermitUnknownNegative;
  const crf::ConstraintSet set =
      finalized_set(checks, set_id(501), {required, forbidden}, evidence);

  crf::Constraint fail_closed = capability_constraint(
      constraint_id(8), crf::ConstraintKind::ForbiddenCapability, forbidden_capability);
  fail_closed.unknown_policy = crf::UnknownPolicy::FailClosed;
  const crf::ConstraintSet negative_fail_closed =
      finalized_set(checks, set_id(502), {fail_closed}, evidence);

  const crf::CandidatePath satisfied = finalized_candidate(
      checks, with_capability(candidate_path(evidence, path_id(51), {node_id(51), node_id(52)}),
                              required_capability, evidence.capability));
  const crf::CandidatePath missing = finalized_candidate(
      checks, with_capability_on_nodes(
                  candidate_path(evidence, path_id(52), {node_id(53), node_id(54)}),
                  required_capability, evidence.capability));
  const crf::CandidatePath present = finalized_candidate(
      checks,
      with_capability(with_capability(candidate_path(evidence, path_id(53),
                                                     {node_id(55), node_id(56)}),
                                      required_capability, evidence.capability),
                      forbidden_capability, evidence.capability));

  const crf::EvaluationRecord satisfied_record =
      evaluate_checked(checks, set, evidence, satisfied, evaluation_generation(1));
  const crf::EvaluationRecord missing_record =
      evaluate_checked(checks, set, evidence, missing, evaluation_generation(2));
  const crf::EvaluationRecord present_record =
      evaluate_checked(checks, set, evidence, present, evaluation_generation(3));

  checks.expect(satisfied_record.outcome == crf::Outcome::Admissible,
                "a path where every node and link attests the required capability is admissible "
                "[actual=" + verdict_text(satisfied_record) + "]");
  checks.expect(missing_record.outcome == crf::Outcome::UnknownRequiredEvidence &&
                    missing_record.primary_reason ==
                        crf::ReasonCode::CapabilityEvidenceUnavailable,
                "a path missing the required capability on its links is "
                "UNKNOWN_REQUIRED_EVIDENCE/CAPABILITY_EVIDENCE_UNAVAILABLE [actual=" +
                    verdict_text(missing_record) + "]");
  const crf::Reason* missing_reason =
      reason_of(missing_record, crf::ReasonCode::CapabilityEvidenceUnavailable);
  checks.expect(missing_reason != nullptr &&
                    missing_reason->subject_kind == crf::SubjectKind::Link,
                "the unavailable evidence is attributed to the entity that lacks it (a link)");
  checks.expect(present_record.outcome == crf::Outcome::HardConstraintFailed &&
                    present_record.primary_reason ==
                        crf::ReasonCode::ForbiddenCapabilityPresent,
                "a path carrying the forbidden capability is HARD_CONSTRAINT_FAILED/"
                "FORBIDDEN_CAPABILITY_PRESENT [actual=" + verdict_text(present_record) + "]");

  const crf::EvaluationRecord fail_closed_record =
      evaluate_checked(checks, negative_fail_closed, evidence, satisfied, evaluation_generation(4));
  checks.expect(fail_closed_record.outcome == crf::Outcome::UnknownRequiredEvidence &&
                    fail_closed_record.primary_reason ==
                        crf::ReasonCode::CapabilityEvidenceUnavailable,
                "with the default fail-closed policy the same absence of evidence is UNKNOWN "
                "rather than a silent pass [actual=" + verdict_text(fail_closed_record) + "]");

  report(checks,
         std::string("capability_requirement: ") + checks.status() + " [all-entities-attested -> " +
             verdict_text(satisfied_record) + "; link-missing-required -> " +
             verdict_text(missing_record) + "; forbidden-present -> " +
             verdict_text(present_record) + "; fail-closed negative control -> " +
             verdict_text(fail_closed_record) + "]");
}

// ---------------------------------------------------------------------------
// 6. policy_constraint
// ---------------------------------------------------------------------------

void run_policy_constraint(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::PolicyId policy = policy_id(61);
  const crf::PolicyGeneration required_generation = evidence.policy;
  const crf::PolicyGeneration stale_generation =
      crf::PolicyGeneration::from_value(required_generation.value() - 1);

  const crf::ConstraintSet set = finalized_set(
      checks, set_id(601), {administrative_policy(constraint_id(9), policy)}, evidence);

  const crf::CandidatePath attested = finalized_candidate(
      checks, with_policy(candidate_path(evidence, path_id(61), {node_id(61), node_id(62)}), policy,
                          required_generation));
  const crf::CandidatePath absent = finalized_candidate(
      checks, candidate_path(evidence, path_id(62), {node_id(63), node_id(64)}));
  const crf::CandidatePath stale = finalized_candidate(
      checks, with_policy(candidate_path(evidence, path_id(63), {node_id(65), node_id(66)}), policy,
                          stale_generation));

  const crf::EvaluationRecord attested_record =
      evaluate_checked(checks, set, evidence, attested, evaluation_generation(1));
  const crf::EvaluationRecord absent_record =
      evaluate_checked(checks, set, evidence, absent, evaluation_generation(2));
  const crf::EvaluationRecord stale_record =
      evaluate_checked(checks, set, evidence, stale, evaluation_generation(3));

  checks.expect(attested_record.outcome == crf::Outcome::Admissible,
                "a candidate attesting the policy at the required generation passes [actual=" +
                    verdict_text(attested_record) + "]");
  checks.expect(absent_record.outcome == crf::Outcome::HardConstraintFailed &&
                    absent_record.primary_reason ==
                        crf::ReasonCode::AdministrativePolicyNotSatisfied,
                "a candidate with no attestation for that policy fails "
                "ADMINISTRATIVE_POLICY_NOT_SATISFIED [actual=" + verdict_text(absent_record) + "]");
  const crf::Reason* policy_reason =
      reason_of(absent_record, crf::ReasonCode::AdministrativePolicyNotSatisfied);
  checks.expect(policy_reason != nullptr && policy_reason->subject_kind == crf::SubjectKind::Policy &&
                    policy_reason->subject == policy.value(),
                "the failure names the exact policy identity that is unattested");
  checks.expect(stale_record.outcome == crf::Outcome::UnknownRequiredEvidence &&
                    stale_record.primary_reason == crf::ReasonCode::PolicyEvidenceUnavailable,
                "an attestation at a stale generation is UNKNOWN_REQUIRED_EVIDENCE/"
                "POLICY_EVIDENCE_UNAVAILABLE [actual=" + verdict_text(stale_record) + "]");
  const crf::Reason* stale_reason =
      reason_of(stale_record, crf::ReasonCode::PolicyEvidenceUnavailable);
  checks.expect(stale_reason != nullptr &&
                    stale_reason->expected == required_generation.value() &&
                    stale_reason->actual == stale_generation.value(),
                "the stale attestation names the required and the attested generations");

  report(checks,
         std::string("policy_constraint: ") + checks.status() + " [policy " +
             std::to_string(policy.value()) + " at generation " +
             std::to_string(required_generation.value()) + " -> " + verdict_text(attested_record) +
             "; no attestation -> " + verdict_text(absent_record) + "; generation " +
             std::to_string(stale_generation.value()) + " -> " + verdict_text(stale_record) + "]");
}

// ---------------------------------------------------------------------------
// 7. contradictory_constraint_rejection
// ---------------------------------------------------------------------------

void run_contradictory_constraint_rejection(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::NodeId disputed = node_id(71);

  crf::ConstraintSet input;
  input.id = set_id(701);
  input.generation = crf::ConstraintSetGeneration::from_value(1);
  input.state = crf::ConstraintSetState::Declared;
  input.name = "contradictory-synthetic";
  input.evidence = evidence;
  // Deliberately not canonical: the required-node list is unsorted, so any
  // in-place canonicalization would be visible in the encoded bytes.
  input.constraints.push_back(
      node_constraint(constraint_id(11), crf::ConstraintKind::RequiredNode,
                      {node_id(72), disputed, disputed}));
  input.constraints.push_back(
      node_constraint(constraint_id(12), crf::ConstraintKind::ForbiddenNode, {disputed}));

  const std::vector<crf::Constraint> constraints_before = input.constraints;
  const crf::Digest256 digest_before = input.digest;
  crf::ByteWriter before_writer;
  crf::encode_constraint_set(before_writer, input);
  const std::vector<std::byte> bytes_before = before_writer.buffer();

  std::vector<crf::SetDefect> defects;
  std::vector<crf::Contradiction> contradictions;
  const crf::Status status =
      crf::validate_and_finalize_constraint_set(input, kLimits, defects, contradictions);

  crf::ByteWriter after_writer;
  crf::encode_constraint_set(after_writer, input);
  const std::vector<std::byte> bytes_after = after_writer.buffer();

  checks.expect(status.code() == crf::ErrorCode::ContradictoryConstraintSet,
                "the contradictory set is rejected with ErrorCode::ContradictoryConstraintSet "
                "[actual=" + code_text(status.code()) + " " + status.detail() + "]");
  checks.expect(!contradictions.empty(), "the contradiction list is non-empty");
  checks.expect(!contradictions.empty() &&
                    contradictions.front().kind ==
                        crf::ContradictionKind::RequiredAndForbiddenSameEntity,
                "the contradiction is RequiredAndForbiddenSameEntity");
  checks.expect(!contradictions.empty() &&
                    contradictions.front().subject_kind == crf::SubjectKind::Node &&
                    contradictions.front().subject == disputed.value(),
                "the contradiction names the disputed node identity");
  checks.expect(!contradictions.empty() &&
                    contradictions.front().first == constraint_id(11) &&
                    contradictions.front().second == constraint_id(12),
                "the contradiction names the required and the forbidden constraint");
  checks.expect(!defects.empty(),
                "canonicalization observations are reported to the caller (they were computed on "
                "a working copy)");

  checks.expect(bytes_after == bytes_before,
                "the caller's constraint set is byte-identical after the atomic rejection");
  checks.expect(input.constraints == constraints_before,
                "every constraint of the caller's set is untouched, including the deliberately "
                "unsorted entity list");
  checks.expect(input.digest == digest_before && input.digest.is_zero(),
                "the caller's set digest was never recomputed");
  checks.expect(input.id == set_id(701) && input.generation.value() == 1 &&
                    input.state == crf::ConstraintSetState::Declared &&
                    input.name == "contradictory-synthetic",
                "identity, generation, lifecycle state and name are unchanged");

  report(checks,
         std::string("contradictory_constraint_rejection: ") + checks.status() + " [status=" +
             code_text(status.code()) + "; contradictions=" +
             std::to_string(contradictions.size()) + " kind=" +
             (contradictions.empty() ? std::string("none")
                                     : crf::to_string(contradictions.front().kind)) +
             " subject=" +
             (contradictions.empty() ? std::string("none")
                                     : std::to_string(contradictions.front().subject)) +
             "; encoded bytes identical=" + (bytes_after == bytes_before ? "true" : "false") + "]");
}

// ---------------------------------------------------------------------------
// 8. stale_evidence
// ---------------------------------------------------------------------------

void run_stale_evidence(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::CapabilityId capability = capability_id(81);
  const crf::ConstraintSetId definition_id = set_id(801);
  const crf::CandidatePath candidate = finalized_candidate(
      checks, with_capability(candidate_path(evidence, path_id(81), {node_id(81), node_id(82)}),
                              capability, evidence.capability));
  const std::vector<crf::CandidatePath> population{candidate};

  crf::ManualClock clock{1000};
  crf::Result<std::unique_ptr<crf::Coordinator>> opened =
      crf::Coordinator::open_in_memory(coordinator_config(evidence), &clock);
  checks.expect_ok(opened, "the in-memory coordinator opens");
  if (!opened.ok()) {
    report(checks, std::string("stale_evidence: ") + checks.status() + " [coordinator unavailable]");
    return;
  }
  std::unique_ptr<crf::Coordinator> coordinator = std::move(opened.value());
  AttemptSequencer sequencer(coordinator->epoch());

  const crf::Result<crf::PublisherRegistration> registration = coordinator->register_publisher(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      publisher_id(1), worker_boot(0xD1), publisher_scopes(), session_id(1));
  checks.expect_ok(registration, "the synthetic publisher registers for the current epoch");

  const crf::ConstraintSet definition =
      required_capability_definition(checks, evidence, definition_id, capability);
  const crf::Result<crf::ConstraintSet> published = coordinator->publish_constraint_set(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      definition);
  checks.expect_ok(published, "the definition is published");
  const crf::Result<crf::ConstraintSet> activated = coordinator->apply_lifecycle(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      definition_id, crf::LifecycleEvent::Activate);
  checks.expect_ok(activated, "the definition is activated");
  checks.expect(activated.ok() && activated.value().state == crf::ConstraintSetState::Active,
                "only an Active set can publish an admissible outcome");

  const crf::Result<crf::CommitOutcome> bound = coordinator->evaluate(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      definition_id, population);
  checks.expect_ok(bound, "the coordinator evaluates the candidate at the bound generation");
  const crf::EvaluationRecord* bound_record =
      bound.ok() ? record_for(bound.value().batch, candidate.path) : nullptr;
  checks.expect(bound.ok() && bound.value().committed,
                "the evaluation commits while the candidate's generation is the required one");
  checks.expect(bound_record != nullptr && bound_record->outcome == crf::Outcome::Admissible,
                "the candidate is ADMISSIBLE at the capability generation it binds [actual=" +
                    (bound_record == nullptr ? std::string("missing")
                                             : verdict_text(*bound_record)) + "]");

  const std::uint64_t advanced_generation = evidence.capability.value() + 1;
  const crf::Status advanced = coordinator->advance_family(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      crf::EvidenceFamily::Capability, advanced_generation);
  checks.expect_ok(advanced, "the coordinator-side capability requirement advances");
  checks.expect(coordinator->evidence_requirements().capability.value() == advanced_generation,
                "the coordinator now requires capability generation " +
                    std::to_string(advanced_generation));

  const crf::Result<crf::CommitOutcome> stale = coordinator->evaluate(
      sequencer.next(publisher_id(1), worker_boot(0xD1), session_id(1), publisher_scopes()),
      definition_id, population);
  checks.expect_ok(stale, "the coordinator re-evaluates the same candidate after the advance");
  const crf::EvaluationRecord* stale_record =
      stale.ok() ? record_for(stale.value().batch, candidate.path) : nullptr;
  checks.expect(stale.ok() && stale.value().committed,
                "the re-evaluation itself commits; staleness is an outcome, not an error");
  checks.expect(stale_record != nullptr && stale_record->outcome == crf::Outcome::StaleEvidence,
                "the same candidate is STALE_EVIDENCE once the requirement advances [actual=" +
                    (stale_record == nullptr ? std::string("missing")
                                             : verdict_text(*stale_record)) + "]");
  checks.expect(stale_record != nullptr &&
                    stale_record->primary_reason == crf::ReasonCode::StaleCapabilityEvidence,
                "the primary reason is STALE_CAPABILITY_EVIDENCE [actual=" +
                    (stale_record == nullptr ? std::string("missing")
                                             : reason_text(stale_record->primary_reason)) + "]");
  checks.expect(bound_record != nullptr && stale_record != nullptr &&
                    crf::same_evidence_binding(bound_record->evidence, stale_record->evidence),
                "both evaluations bind the identical candidate evidence; only the requirement moved");

  report(checks,
         std::string("stale_evidence: ") + checks.status() + " [capability generation " +
             std::to_string(evidence.capability.value()) + " -> " +
             (bound_record == nullptr ? std::string("missing") : verdict_text(*bound_record)) +
             "; advanced requirement " + std::to_string(advanced_generation) + " -> " +
             (stale_record == nullptr ? std::string("missing") : verdict_text(*stale_record)) +
             "]");
}

// ---------------------------------------------------------------------------
// 9. worker_reincarnation
// ---------------------------------------------------------------------------

void run_worker_reincarnation(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::CapabilityId capability = capability_id(91);
  const crf::ConstraintSetId definition_id = set_id(901);
  const crf::CandidatePath candidate = finalized_candidate(
      checks, with_capability(candidate_path(evidence, path_id(91), {node_id(91), node_id(92)}),
                              capability, evidence.capability));
  const std::vector<crf::CandidatePath> population{candidate};

  const crf::PublisherId publisher = publisher_id(1);
  const crf::WorkerBootId boot_a = worker_boot(0xA001);
  const crf::WorkerBootId boot_b = worker_boot(0xB002);
  const crf::WorkerBootId boot_c = worker_boot(0xC003);
  const crf::SessionId session_a = session_id(1);
  const crf::SessionId session_b = session_id(2);
  const crf::SessionId session_c = session_id(3);

  crf::ManualClock clock{1000};
  crf::Result<std::unique_ptr<crf::Coordinator>> opened =
      crf::Coordinator::open_in_memory(coordinator_config(evidence), &clock);
  checks.expect_ok(opened, "the in-memory coordinator opens");
  if (!opened.ok()) {
    report(checks,
           std::string("worker_reincarnation: ") + checks.status() + " [coordinator unavailable]");
    return;
  }
  std::unique_ptr<crf::Coordinator> coordinator = std::move(opened.value());
  AttemptSequencer sequencer(coordinator->epoch());

  const crf::Result<crf::PublisherRegistration> registration_a = coordinator->register_publisher(
      sequencer.next(publisher, boot_a, session_a, publisher_scopes()), publisher, boot_a,
      publisher_scopes(), session_a);
  checks.expect_ok(registration_a, "worker boot A registers for publisher 1");

  const crf::ConstraintSet definition =
      required_capability_definition(checks, evidence, definition_id, capability);
  checks.expect_ok(coordinator->publish_constraint_set(
                       sequencer.next(publisher, boot_a, session_a, publisher_scopes()), definition),
                   "boot A publishes the definition");
  checks.expect_ok(coordinator->apply_lifecycle(
                       sequencer.next(publisher, boot_a, session_a, publisher_scopes()),
                       definition_id, crf::LifecycleEvent::Activate),
                   "boot A activates the definition");
  const crf::Result<crf::CommitOutcome> evaluated_by_a = coordinator->evaluate(
      sequencer.next(publisher, boot_a, session_a, publisher_scopes()), definition_id, population);
  checks.expect_ok(evaluated_by_a, "boot A evaluates the candidate population");
  checks.expect(evaluated_by_a.ok() && evaluated_by_a.value().committed,
                "boot A's evaluation commits");

  // The coordinator observes the transport loss of boot A's session and fences
  // the boot through the registry semantics it owns.
  const crf::Status fenced = coordinator->fence_on_session_loss(session_a);
  checks.expect_ok(fenced, "the coordinator fences the boot that owned the lost session");
  checks.expect(coordinator->authority().is_boot_fenced(boot_a),
                "worker boot A is fenced in the live authority registry");

  const crf::Result<crf::ConstraintSet> fenced_mutation = coordinator->publish_constraint_set(
      sequencer.next(publisher, boot_a, session_a, publisher_scopes()), definition);
  checks.expect(!fenced_mutation.ok(), "a mutation carrying the fenced boot is rejected");
  checks.expect(fenced_mutation.code() == crf::ErrorCode::Fenced ||
                    fenced_mutation.code() == crf::ErrorCode::Unauthorized,
                "the rejection is UNAUTHORIZED/FENCED [actual=" +
                    code_text(fenced_mutation.code()) + " " + fenced_mutation.detail() + "]");
  checks.expect(fenced_mutation.code() == crf::ErrorCode::Fenced,
                "specifically, the fenced boot is refused with FENCED [actual=" +
                    code_text(fenced_mutation.code()) + "]");

  const crf::Result<crf::PublisherRegistration> rejoin_a = coordinator->register_publisher(
      sequencer.next(publisher, boot_a, session_id(4), publisher_scopes()), publisher, boot_a,
      publisher_scopes(), session_id(4));
  checks.expect(!rejoin_a.ok() && rejoin_a.code() == crf::ErrorCode::Fenced,
                "a fenced boot can never register again [actual=" + code_text(rejoin_a.code()) +
                    " " + rejoin_a.detail() + "]");

  const crf::Result<crf::PublisherRegistration> registration_b = coordinator->register_publisher(
      sequencer.next(publisher, boot_b, session_b, publisher_scopes()), publisher, boot_b,
      publisher_scopes(), session_b);
  checks.expect_ok(registration_b, "the reincarnated worker boot B registers successfully");
  checks.expect(!coordinator->authority().is_boot_fenced(boot_b),
                "boot B is live, not fenced");
  const crf::Result<crf::CommitOutcome> evaluated_by_b = coordinator->evaluate(
      sequencer.next(publisher, boot_b, session_b, publisher_scopes()), definition_id, population);
  checks.expect_ok(evaluated_by_b, "boot B evaluates the retained population");
  checks.expect(evaluated_by_b.ok() && evaluated_by_b.value().committed,
                "a mutation from the fresh boot succeeds");

  // Reincarnation again: the same publisher registering a further fresh boot
  // fences the previous one through the registry itself.
  const crf::Result<crf::PublisherRegistration> registration_c = coordinator->register_publisher(
      sequencer.next(publisher, boot_c, session_c, publisher_scopes()), publisher, boot_c,
      publisher_scopes(), session_c);
  checks.expect_ok(registration_c, "a third worker boot registers for the same publisher");
  checks.expect(coordinator->authority().is_boot_fenced(boot_b),
                "re-registering with a fresh boot fences the previous boot of that publisher");
  checks.expect(coordinator->authority().live_publishers() == 1,
                "exactly one publisher registration is live");
  const crf::Status reincarnation_mutation = coordinator->set_evidence_requirements(
      sequencer.next(publisher, boot_b, session_b, publisher_scopes()), evidence);
  checks.expect(reincarnation_mutation.code() == crf::ErrorCode::Fenced,
                "the superseded boot B is refused after boot C registered [actual=" +
                    code_text(reincarnation_mutation.code()) + "]");
  const crf::Result<crf::CommitOutcome> evaluated_by_c = coordinator->evaluate(
      sequencer.next(publisher, boot_c, session_c, publisher_scopes()), definition_id, population);
  checks.expect_ok(evaluated_by_c, "boot C evaluates the retained population");
  checks.expect(evaluated_by_c.ok() && evaluated_by_c.value().committed,
                "the newest boot owns the mutation path");

  report(checks,
         std::string("worker_reincarnation: ") + checks.status() +
             " [boot A=" + crf::to_string(boot_a) + " fenced=" +
             (coordinator->authority().is_boot_fenced(boot_a) ? "true" : "false") +
             ", boot B=" + crf::to_string(boot_b) + " fenced=" +
             (coordinator->authority().is_boot_fenced(boot_b) ? "true" : "false") +
             ", boot C=" + crf::to_string(boot_c) + " live=true; fenced mutation -> " +
             code_text(fenced_mutation.code()) + "]");
}

// ---------------------------------------------------------------------------
// 10. coordinator_restart
// ---------------------------------------------------------------------------

void run_coordinator_restart(Checks& checks) {
  const crf::EvidenceRequirements evidence = fixture_evidence();
  const crf::CapabilityId capability = capability_id(101);
  const crf::ConstraintSetId definition_id = set_id(1001);
  const crf::CandidatePath candidate = finalized_candidate(
      checks, with_capability(candidate_path(evidence, path_id(101), {node_id(101), node_id(102)}),
                              capability, evidence.capability));
  const std::vector<crf::CandidatePath> population{candidate};

  std::error_code error;
  const std::filesystem::path base = std::filesystem::temp_directory_path(error);
  checks.expect(!error, "the temporary directory root resolves");
  if (error) {
    report(checks,
           std::string("coordinator_restart: ") + checks.status() + " [no temporary directory]");
    return;
  }
  const std::filesystem::path directory = base / "crf_examples_coordinator_restart";
  (void)std::filesystem::remove_all(directory, error);
  error.clear();
  (void)std::filesystem::create_directories(directory, error);
  checks.expect(!error, "a fresh temporary store directory is created");
  if (error) {
    report(checks,
           std::string("coordinator_restart: ") + checks.status() + " [store directory failed]");
    return;
  }
  const std::filesystem::path store = directory / "store.bin";

  crf::CoordinatorConfig config = coordinator_config(evidence);
  config.store_path = store.string();
  config.allow_initialize = true;
  crf::ManualClock clock{1000};

  const crf::ConstraintSet definition =
      required_capability_definition(checks, evidence, definition_id, capability);
  const crf::Digest256 definition_digest = definition.digest;

  crf::CoordinatorEpoch first_epoch;
  crf::ConstraintSetGeneration definition_generation;
  {
    crf::Result<std::unique_ptr<crf::Coordinator>> opened =
        crf::Coordinator::open(config, &clock);
    checks.expect_ok(opened, "the durable coordinator opens on an empty store");
    if (!opened.ok()) {
      (void)std::filesystem::remove_all(directory, error);
      report(checks, std::string("coordinator_restart: ") + checks.status() +
                         " [durable coordinator unavailable]");
      return;
    }
    std::unique_ptr<crf::Coordinator> coordinator = std::move(opened.value());
    first_epoch = coordinator->epoch();
    AttemptSequencer sequencer(first_epoch);

    checks.expect_ok(coordinator->register_publisher(
                         sequencer.next(publisher_id(1), worker_boot(0xE1), session_id(1),
                                        publisher_scopes()),
                         publisher_id(1), worker_boot(0xE1), publisher_scopes(), session_id(1)),
                     "a publisher registers on the durable coordinator");
    const crf::Result<crf::ConstraintSet> published = coordinator->publish_constraint_set(
        sequencer.next(publisher_id(1), worker_boot(0xE1), session_id(1), publisher_scopes()),
        definition);
    checks.expect_ok(published, "the definition is published durably");
    checks.expect_ok(coordinator->apply_lifecycle(
                         sequencer.next(publisher_id(1), worker_boot(0xE1), session_id(1),
                                        publisher_scopes()),
                         definition_id, crf::LifecycleEvent::Activate),
                     "the definition is activated durably");
    definition_generation = published.ok() ? published.value().generation
                                           : crf::ConstraintSetGeneration::from_value(1);
    const crf::Result<crf::CommitOutcome> evaluated = coordinator->evaluate(
        sequencer.next(publisher_id(1), worker_boot(0xE1), session_id(1), publisher_scopes()),
        definition_id, population);
    checks.expect_ok(evaluated, "the durable coordinator evaluates the population");
    const crf::EvaluationRecord* record =
        evaluated.ok() ? record_for(evaluated.value().batch, candidate.path) : nullptr;
    checks.expect(evaluated.ok() && evaluated.value().committed && record != nullptr &&
                      record->outcome == crf::Outcome::Admissible,
                  "an admissible result is current before the restart");
    const crf::Result<crf::CurrentnessReport> before = coordinator->currentness(definition_id);
    checks.expect(before.ok() && before.value().current_results == population.size(),
                  "the pre-restart state reports " + std::to_string(population.size()) +
                      " current result(s)");
    // Drop the coordinator object entirely; only the store file survives.
    coordinator.reset();
  }

  crf::Result<std::unique_ptr<crf::Coordinator>> reopened =
      crf::Coordinator::open(config, &clock);
  checks.expect_ok(reopened, "a brand new coordinator opens on the same store path");
  if (!reopened.ok()) {
    (void)std::filesystem::remove_all(directory, error);
    report(checks, std::string("coordinator_restart: ") + checks.status() +
                       " [re-open failed: " + code_text(reopened.code()) + "]");
    return;
  }
  std::unique_ptr<crf::Coordinator> coordinator = std::move(reopened.value());
  const crf::CoordinatorEpoch second_epoch = coordinator->epoch();
  checks.expect(second_epoch > first_epoch,
                "the coordinator epoch advanced strictly across the restart (" +
                    crf::to_string(first_epoch) + " -> " + crf::to_string(second_epoch) + ")");

  const crf::Result<crf::ConstraintSet> restored = coordinator->get_constraint_set(definition_id);
  checks.expect_ok(restored, "the constraint definition survived the restart");
  checks.expect(restored.ok() && restored.value().digest == definition_digest,
                "the restored definition carries the same semantic digest");
  checks.expect(restored.ok() && restored.value().generation == definition_generation &&
                    restored.value().state == crf::ConstraintSetState::Active,
                "the restored definition keeps its generation and Active lifecycle state");

  const crf::Result<crf::CurrentnessReport> recovered = coordinator->currentness(definition_id);
  checks.expect_ok(recovered, "currentness is reported for the restored definition");
  checks.expect(recovered.ok() && recovered.value().current_results == 0,
                "no result is restored as current [actual current_results=" +
                    std::to_string(recovered.ok() ? recovered.value().current_results : 0) + "]");
  checks.expect(recovered.ok() && recovered.value().recovered_unproven == population.size(),
                "every stored result is reported as RecoveredUnproven");
  checks.expect(recovered.ok() && has_cause(recovered.value(), crf::CurrentnessCause::RecoveredUnproven),
                "the currentness causes name RecoveredUnproven");
  checks.expect(recovered.ok() && has_cause(recovered.value(), crf::CurrentnessCause::NoCurrentResult),
                "the currentness causes name NoCurrentResult");
  const crf::Result<crf::EvaluationRecord> stale_lookup =
      coordinator->current_result(definition_id, candidate.path);
  checks.expect(!stale_lookup.ok() && stale_lookup.code() == crf::ErrorCode::NotFound,
                "no current result is addressable for the restored path [actual=" +
                    code_text(stale_lookup.code()) + "]");

  // Live authority is never restored, so the new epoch needs its own
  // registration.
  AttemptSequencer sequencer(second_epoch);
  const crf::WorkerBootId boot = worker_boot(0xE2);
  const crf::SessionId session = session_id(2);
  checks.expect_ok(coordinator->register_publisher(
                       sequencer.next(publisher_id(1), boot, session, publisher_scopes()),
                       publisher_id(1), boot, publisher_scopes(), session),
                   "a publisher registers in the new epoch");

  // An evaluation identity is derived from its semantic binding, so re-proving
  // exactly the same binding produces exactly the same identity. The recovered
  // record already carries that identity; committing the fresh proof replaces it
  // instead of duplicating it, and the result becomes current again. Nothing is
  // ever restored as current without being re-proven.
  const crf::Result<crf::CommitOutcome> replay = coordinator->evaluate(
      sequencer.next(publisher_id(1), boot, session, publisher_scopes()), definition_id, population);
  checks.expect_ok(replay, "re-proving the identical binding after a restart succeeds");
  if (replay.ok()) {
    checks.expect(replay.value().committed, "the re-proof commits an authoritative result");
    const crf::Result<crf::CurrentnessReport> after_replay = coordinator->currentness(definition_id);
    checks.expect_ok(after_replay, "currentness is readable after the re-proof");
    checks.expect(after_replay.ok() && after_replay.value().current_results == 1 &&
                      after_replay.value().recovered_unproven == 0,
                  "re-proving the identical binding restores currentness [current=" +
                      std::to_string(after_replay.ok() ? after_replay.value().current_results : 0) +
                      " recovered=" +
                      std::to_string(after_replay.ok() ? after_replay.value().recovered_unproven : 0) +
                      "]");
  }

  // The fabric moved on during the restart: the capability registry advanced,
  // so the planner re-attests the retained path at the current generation. The
  // constraint definitions themselves are re-published unchanged.
  const std::uint64_t advanced_capability = evidence.capability.value() + 1;
  checks.expect_ok(coordinator->advance_family(
                       sequencer.next(publisher_id(1), boot, session, publisher_scopes()),
                       crf::EvidenceFamily::Capability, advanced_capability),
                   "the capability evidence generation advances after the restart");
  crf::EvidenceRequirements current_evidence = evidence;
  current_evidence.capability = crf::CapabilityGeneration::from_value(advanced_capability);
  const crf::CandidatePath rebound = finalized_candidate(
      checks, with_capability(candidate_path(current_evidence, path_id(101), {node_id(101), node_id(102)}),
                              capability, current_evidence.capability));
  const std::vector<crf::CandidatePath> rebound_population{rebound};

  const crf::Result<crf::ConstraintSet> republished = coordinator->publish_constraint_set(
      sequencer.next(publisher_id(1), boot, session, publisher_scopes()), definition);
  checks.expect_ok(republished, "the same definitions are re-published");
  checks.expect(republished.ok() && republished.value().digest == definition_digest &&
                    republished.value().generation == definition_generation,
                "re-publishing identical semantics advances nothing");

  const crf::Result<crf::CommitOutcome> re_evaluated = coordinator->evaluate(
      sequencer.next(publisher_id(1), boot, session, publisher_scopes()), definition_id,
      rebound_population);
  checks.expect_ok(re_evaluated, "the restored definition is re-evaluated");
  const crf::EvaluationRecord* record =
      re_evaluated.ok() ? record_for(re_evaluated.value().batch, rebound.path) : nullptr;
  checks.expect(re_evaluated.ok() && re_evaluated.value().committed && record != nullptr &&
                    record->outcome == crf::Outcome::Admissible,
                "admissible results are published again after the restart [actual=" +
                    (record == nullptr ? std::string("missing") : verdict_text(*record)) + "]");
  const crf::Result<crf::CurrentnessReport> after = coordinator->currentness(definition_id);
  checks.expect(after.ok() && after.value().current_results == rebound_population.size(),
                "admissible results are current again [actual current_results=" +
                    std::to_string(after.ok() ? after.value().current_results : 0) + "]");
  const crf::Result<crf::EvaluationRecord> current_lookup =
      coordinator->current_result(definition_id, rebound.path);
  checks.expect(current_lookup.ok() &&
                    current_lookup.value().outcome == crf::Outcome::Admissible,
                "the current result index answers for the re-evaluated path");

  coordinator.reset();
  (void)std::filesystem::remove_all(directory, error);
  checks.expect(!error && !std::filesystem::exists(store),
                "the temporary store directory is deleted at the end of the scenario");

  report(checks,
         std::string("coordinator_restart: ") + checks.status() + " [epoch " +
             crf::to_string(first_epoch) + " -> " + crf::to_string(second_epoch) +
             "; digest preserved=" + (restored.ok() && restored.value().digest == definition_digest
                                          ? "true"
                                          : "false") +
             "; recovered current_results=0 causes=" +
             (recovered.ok() ? cause_text(recovered.value()) : std::string("unavailable")) +
             "; identical replay -> " + code_text(replay.code()) + "; capability requirement " +
             std::to_string(evidence.capability.value()) + " -> " +
             std::to_string(advanced_capability) + "; after re-publish+re-evaluate current_results=" +
             std::to_string(after.ok() ? after.value().current_results : 0) + "]");
}

// ---------------------------------------------------------------------------
// Scenario registry and driver
// ---------------------------------------------------------------------------

struct ScenarioEntry {
  std::string_view name;
  void (*run)(Checks&);
};

constexpr std::array<ScenarioEntry, 10> kScenarios = {{
    {"latency_bound", run_latency_bound},
    {"bandwidth_capability", run_bandwidth_capability},
    {"forbidden_topology_entity", run_forbidden_topology_entity},
    {"locality", run_locality},
    {"capability_requirement", run_capability_requirement},
    {"policy_constraint", run_policy_constraint},
    {"contradictory_constraint_rejection", run_contradictory_constraint_rejection},
    {"stale_evidence", run_stale_evidence},
    {"worker_reincarnation", run_worker_reincarnation},
    {"coordinator_restart", run_coordinator_restart},
}};

}  // namespace

int main(int argc, char** argv) {
  std::cout << "crf_examples: synthetic fixture evidence only "
               "(EvidenceProvenance::SyntheticFixture); no measured telemetry is used.\n";
  if (argc > 2) {
    std::cout << "usage: crf_examples [scenario-name]\n";
    return 2;
  }
  const std::string_view selected = argc == 2 ? std::string_view(argv[1]) : std::string_view();
  if (!selected.empty()) {
    bool known = false;
    for (const ScenarioEntry& entry : kScenarios) {
      known = known || entry.name == selected;
    }
    if (!known) {
      std::cout << "unknown scenario '" << selected << "'; known scenarios:";
      for (const ScenarioEntry& entry : kScenarios) {
        std::cout << ' ' << entry.name;
      }
      std::cout << '\n';
      return 2;
    }
  }

  std::size_t scenarios_ran = 0;
  std::size_t scenarios_failed = 0;
  std::size_t checks_total = 0;
  std::size_t checks_failed = 0;
  for (const ScenarioEntry& entry : kScenarios) {
    if (!selected.empty() && entry.name != selected) {
      continue;
    }
    Checks checks(std::string(entry.name));
    entry.run(checks);
    ++scenarios_ran;
    scenarios_failed += checks.failures() == 0 ? 0u : 1u;
    checks_total += checks.checks();
    checks_failed += static_cast<std::size_t>(checks.failures());
  }

  std::cout << "summary: scenarios=" << scenarios_ran << " failed_scenarios=" << scenarios_failed
            << " checks=" << checks_total << " failed_checks=" << checks_failed << '\n';
  std::cout << "result: " << (scenarios_failed == 0 ? "PASS" : "FAIL") << '\n';
  return scenarios_failed == 0 ? 0 : 1;
}
