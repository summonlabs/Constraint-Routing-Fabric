// Constraint Routing Fabric -- independent consumer.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This program is deliberately NOT part of the library build. It is configured
// separately against an installed package prefix and uses only the public
// headers, which is what proves the package is self-contained.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <constraint_routing_fabric/fabric.hpp>

namespace {

using namespace crf;  // NOLINT(google-build-using-namespace)

int failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "FAIL %s\n", what);
    ++failures;
  }
}

[[nodiscard]] NodeId node(std::uint64_t value) { return NodeId::from_value(value); }
[[nodiscard]] LinkId link(std::uint64_t value) { return LinkId::from_value(value); }
[[nodiscard]] CapabilityId capability(std::uint64_t value) { return CapabilityId::from_value(value); }

/// A bounded constraint set built entirely through the public API.
[[nodiscard]] ConstraintSet bounded_set(const EvidenceRequirements& evidence) {
  ConstraintSet set;
  set.id = ConstraintSetId::from_value(1);
  set.generation = ConstraintSetGeneration::from_value(1);
  set.state = ConstraintSetState::Active;
  set.evidence = evidence;
  set.name = "consumer";

  Constraint forbidden;
  forbidden.id = ConstraintId::from_value(1);
  forbidden.generation = ConstraintGeneration::from_value(1);
  forbidden.kind = ConstraintKind::ForbiddenNode;
  forbidden.scope = ConstraintScope::Mandatory;
  forbidden.nodes = {node(77)};
  set.constraints.push_back(forbidden);

  Constraint hops;
  hops.id = ConstraintId::from_value(2);
  hops.generation = ConstraintGeneration::from_value(1);
  hops.kind = ConstraintKind::MaxHopCount;
  hops.scope = ConstraintScope::Mandatory;
  hops.bound = 4;
  set.constraints.push_back(hops);

  Constraint needs_capability;
  needs_capability.id = ConstraintId::from_value(3);
  needs_capability.generation = ConstraintGeneration::from_value(1);
  needs_capability.kind = ConstraintKind::RequiredCapability;
  needs_capability.scope = ConstraintScope::Mandatory;
  needs_capability.capabilities = {capability(9)};
  set.constraints.push_back(needs_capability);

  Constraint preference;
  preference.id = ConstraintId::from_value(4);
  preference.generation = ConstraintGeneration::from_value(1);
  preference.kind = ConstraintKind::MaxLatency;
  preference.scope = ConstraintScope::Preference;
  preference.latency_source = LatencySource::PlannerCost;
  preference.bound = 5000;
  preference.preference_rank = 1;
  preference.preference_weight = 3;
  set.constraints.push_back(preference);

  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  const Status status =
      validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
  if (!status.ok()) {
    std::fprintf(stderr, "FAIL fixture: %s %s\n", to_string(status.code()), status.detail().c_str());
    ++failures;
  }
  return set;
}

[[nodiscard]] CandidatePath make_candidate(PathId path, std::vector<NodeId> nodes, LinkId first_link,
                                           std::int64_t latency, bool with_capability,
                                           const EvidenceRequirements& evidence) {
  CandidatePath candidate;
  candidate.path = path;
  candidate.authority_generation = evidence.path_authority;
  candidate.authority_verdict = PathAuthorityVerdict::Legal;
  candidate.planner_generation = evidence.planner;
  candidate.has_planner_rank = true;
  candidate.planner_rank = static_cast<std::uint32_t>(path.value() % 7);
  candidate.evidence.topology = evidence.topology;
  candidate.evidence.link_state = evidence.link_state;
  candidate.evidence.capability = evidence.capability;
  candidate.evidence.failure_domain = evidence.failure_domain;
  candidate.evidence.policy = evidence.policy;
  candidate.evidence.planner = evidence.planner;
  candidate.evidence.path_authority = evidence.path_authority;
  candidate.evidence.captured_tick = 42;
  for (const NodeId& value : nodes) {
    NodeFact fact;
    fact.node = value;
    if (with_capability) {
      fact.capabilities.push_back(CapabilityRef{capability(9), evidence.capability});
    }
    candidate.nodes.push_back(fact);
  }
  for (std::size_t index = 0; index + 1 < nodes.size(); ++index) {
    LinkFact fact;
    fact.link = LinkId::from_value(first_link.value() + index);
    fact.endpoints[0] = nodes[index];
    fact.endpoints[1] = nodes[index + 1];
    fact.bandwidth.model = CapabilityModel::DeclaredCapabilityRegistry;
    fact.bandwidth.provenance = EvidenceProvenance::FabricCapabilityRegistry;
    fact.bandwidth.bits_per_second = 1000000000LL;
    fact.bandwidth.generation = evidence.capability;
    if (with_capability) {
      fact.capabilities.push_back(CapabilityRef{capability(9), evidence.capability});
    }
    candidate.links.push_back(fact);
  }
  candidate.hop_count = static_cast<std::uint32_t>(candidate.links.size());
  if (latency != 0) {
    candidate.latency.source = LatencySource::PlannerCost;
    candidate.latency.provenance = EvidenceProvenance::PlannerModel;
    candidate.latency.micros = latency;
    candidate.latency.planner_generation = evidence.planner;
  }
  return candidate;
}

}  // namespace

int main() {
  std::printf("consumer: %s\n", version_string().c_str());

  EvidenceRequirements evidence;
  evidence.topology = TopologyGeneration::from_value(3);
  evidence.link_state = LinkStateGeneration::from_value(4);
  evidence.capability = CapabilityGeneration::from_value(5);
  evidence.failure_domain = FailureDomainGeneration::from_value(6);
  evidence.policy = PolicyGeneration::from_value(7);
  evidence.planner = PlannerGeneration::from_value(8);
  evidence.path_authority = PathAuthorityGeneration::from_value(9);

  ConstraintSet set = bounded_set(evidence);
  check(set.constraints.size() == 4, "bounded constraint set has four constraints");
  check(!set.digest.is_zero(), "constraint set has a semantic digest");

  std::vector<CandidatePath> candidates;
  candidates.push_back(make_candidate(PathId::from_value(11), {node(10), node(11), node(12)},
                                      link(100), 4000, true, evidence));
  candidates.push_back(make_candidate(PathId::from_value(12), {node(10), node(77), node(12)},
                                      link(200), 1000, true, evidence));
  candidates.push_back(make_candidate(PathId::from_value(13), {node(10), node(11), node(12)},
                                      link(300), 4000, false, evidence));
  candidates.push_back(make_candidate(PathId::from_value(14), {node(20), node(21)},
                                      link(400), 4800, true, evidence));

  EvaluationContext context;
  context.set = &set;
  context.current = evidence;
  context.limits = nullptr;
  const Limits limits;
  context.limits = &limits;
  context.now_tick = 100;
  context.provenance.epoch = CoordinatorEpoch::from_value(1);
  context.provenance.publisher = PublisherId::from_value(1);
  context.provenance.worker_boot = WorkerBootId::from_value(1);
  context.provenance.attempt = MutationAttemptId::from_value(1);
  context.provenance.request = RequestId::from_value(1);
  context.generation = EvaluationGeneration::from_value(1);
  context.authority_verified = true;

  const Result<EvaluationBatch> batch = evaluate_batch(context, candidates);
  if (!batch.ok()) {
    std::fprintf(stderr, "FAIL evaluate_batch: %s\n", to_string(batch.code()));
    return 1;
  }
  for (const EvaluationRecord& record : batch.value().records) {
    std::printf("candidate %llu -> %s (%s)\n",
                static_cast<unsigned long long>(record.path.value()), to_string(record.outcome),
                to_string(record.primary_reason));
  }

  // A hard exclusion: the forbidden node excludes candidate 12 outright.
  const EvaluationRecord* excluded = nullptr;
  const EvaluationRecord* unknown = nullptr;
  for (const EvaluationRecord& record : batch.value().records) {
    if (record.path == PathId::from_value(12)) {
      excluded = &record;
    }
    if (record.path == PathId::from_value(13)) {
      unknown = &record;
    }
  }
  check(excluded != nullptr, "the excluded candidate is present");
  if (excluded != nullptr) {
    check(excluded->outcome == Outcome::HardConstraintFailed, "the hard exclusion held");
    check(excluded->primary_reason == ReasonCode::ForbiddenNodePresent,
          "the exclusion names the forbidden node");
  }
  check(unknown != nullptr, "the unknown-evidence candidate is present");
  if (unknown != nullptr) {
    check(unknown->outcome == Outcome::UnknownRequiredEvidence,
          "missing capability evidence is unknown, never a pass");
  }

  // Deterministic admissible ordering: two admissible candidates, ordered by the
  // preference margin first and the documented identity tie-break last.
  check(batch.value().admissible_order.size() == 2, "two admissible candidates");
  if (batch.value().admissible_order.size() == 2) {
    const PathId first = batch.value().admissible_order[0].path;
    const PathId second = batch.value().admissible_order[1].path;
    std::printf("admissible order: %llu then %llu\n",
                static_cast<unsigned long long>(first.value()),
                static_cast<unsigned long long>(second.value()));
    // Candidate 14 has a smaller margin (4800 against 5000) than candidate 11
    // (4000 against 5000), so candidate 11 must rank first.
    check(first == PathId::from_value(11), "the better preference margin ranks first");
    // The same population in the opposite order produces the same sequence.
    std::vector<CandidatePath> reversed(candidates.rbegin(), candidates.rend());
    const Result<EvaluationBatch> again = evaluate_batch(context, reversed);
    check(again.ok(), "reversed population evaluates");
    if (again.ok()) {
      check(again.value().admissible_order.size() == 2, "reversed order is admissible");
      if (again.value().admissible_order.size() == 2) {
        check(again.value().admissible_order[0].path == first, "the order is arrival independent");
      }
    }
  }

  std::printf(failures == 0 ? "consumer: PASS\n" : "consumer: FAIL\n");
  return failures == 0 ? 0 : 1;
}
