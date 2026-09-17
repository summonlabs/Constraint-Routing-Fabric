// Constraint Routing Fabric -- two-phase evaluation, races and invalidation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every race here is driven by an explicit phase hook, never by a sleep.
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

[[nodiscard]] std::vector<CandidatePath> population(const EvidenceRequirements& evidence) {
  std::vector<CandidatePath> candidates;
  for (std::uint64_t index = 0; index < 3; ++index) {
    PathSpec spec;
    spec.path = pathid(300 + index);
    spec.nodes = {nid(10), nid(11), nid(12)};
    spec.first_link = 3000 + index * 10;
    spec.planner_latency_micros = 3000;
    spec.bandwidth_bits_per_second = 10000000000LL;
    spec.capabilities = {capid(5)};
    spec.policies = {pid(3)};
    spec.domains = {FailureDomainRef{DomainKind::Rack, domain(41)}};
    candidates.push_back(build_candidate(spec, evidence));
  }
  return candidates;
}

[[nodiscard]] ConstraintSet race_set(const EvidenceRequirements& evidence) {
  std::vector<Constraint> constraints;
  constraints.push_back(with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(11)}));
  constraints.push_back(with_capabilities(cid(2), ConstraintKind::RequiredCapability, {capid(5)}));
  constraints.push_back(with_policies(cid(3), {pid(3)}));
  constraints.push_back(with_nodes(cid(4), ConstraintKind::ForbiddenNode, {nid(99)}));
  constraints.push_back(required_domain_distinct(cid(5), DomainKind::Rack, 1));
  ConstraintSet set = make_set(setid(10), std::move(constraints), evidence);
  set.name = "race";
  return set;
}

[[nodiscard]] ConstraintSet publish(CoordinatorHarness& harness) {
  const EvidenceRequirements evidence = standard_evidence();
  ConstraintSet set = race_set(evidence);
  const Result<ConstraintSet> published =
      harness.coordinator->publish_constraint_set(harness.next_context(), set);
  if (!published.ok()) {
    CRF_FAIL(std::string("publish failed: ") + to_string(published.code()) + " " + published.detail());
    return set;
  }
  const Result<ConstraintSet> activated =
      harness.coordinator->apply_lifecycle(harness.next_context(), published.value().id,
                                           LifecycleEvent::Activate);
  if (!activated.ok()) {
    CRF_FAIL(std::string("activate failed: ") + to_string(activated.code()));
    return published.value();
  }
  return activated.value();
}

/// Drives one deterministic race: the hook advances a dependency generation
/// after the dependency snapshot and before commit verification.
void run_race(EvidenceFamily family, ReasonCode expected_reason) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);

  bool advanced = false;
  harness.coordinator->set_phase_hook([&](CoordinatorPhase phase) {
    if (phase != CoordinatorPhase::AfterDependencySnapshot || advanced) {
      return;
    }
    advanced = true;
    std::uint64_t next = 0;
    switch (family) {
      case EvidenceFamily::Capability: next = evidence.capability.value() + 1; break;
      case EvidenceFamily::Topology: next = evidence.topology.value() + 1; break;
      case EvidenceFamily::Policy: next = evidence.policy.value() + 1; break;
      case EvidenceFamily::FailureDomain: next = evidence.failure_domain.value() + 1; break;
      case EvidenceFamily::PathAuthority: next = evidence.path_authority.value() + 1; break;
      case EvidenceFamily::Planner: next = evidence.planner.value() + 1; break;
      case EvidenceFamily::LinkState: next = evidence.link_state.value() + 1; break;
      default: return;
    }
    const Status status = harness.coordinator->advance_family(harness.next_context(), family, next);
    CRF_CHECK_STATUS(status);
  });

  const Result<CommitOutcome> outcome =
      harness.coordinator->evaluate(harness.next_context(), set.id, candidates);
  CRF_CHECK_RESULT(outcome);
  if (!outcome.ok()) {
    return;
  }
  CRF_CHECK(advanced);
  // The stale completion must leave no authoritative mutation at all.
  CRF_CHECK(!outcome.value().committed);
  CRF_CHECK_EQ(outcome.value().rejection_reason, expected_reason);
  for (const EvaluationRecord& record : outcome.value().batch.records) {
    CRF_CHECK_EQ(record.state, ResultState::StaleAtCommit);
  }
  const Result<CurrentnessReport> currentness = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(currentness);
  CRF_CHECK_EQ(currentness.value().current_results, std::size_t{0});
  CRF_CHECK_EQ(harness.coordinator->stored_evaluation_count(), std::size_t{0});
  const Result<EvaluationRecord> none = harness.coordinator->current_result(set.id, pathid(300));
  CRF_CHECK_EQ(none.code(), ErrorCode::NotFound);
  harness.coordinator->set_phase_hook({});
}

}  // namespace

CRF_TEST(Race, CapabilityGenerationAdvancesDuringEvaluation) {
  run_race(EvidenceFamily::Capability, ReasonCode::StaleCapabilityEvidence);
}

CRF_TEST(Race, TopologyGenerationAdvancesDuringEvaluation) {
  run_race(EvidenceFamily::Topology, ReasonCode::StaleTopologyEvidence);
}

CRF_TEST(Race, PolicyGenerationAdvancesDuringEvaluation) {
  run_race(EvidenceFamily::Policy, ReasonCode::StalePolicyEvidence);
}

CRF_TEST(Race, FailureDomainGenerationAdvancesDuringEvaluation) {
  run_race(EvidenceFamily::FailureDomain, ReasonCode::StaleFailureDomainEvidence);
}

CRF_TEST(Race, PathAuthorityGenerationAdvancesDuringEvaluation) {
  run_race(EvidenceFamily::PathAuthority, ReasonCode::StalePathAuthority);
}

CRF_TEST(Race, UncontendedEvaluationCommitsAndBecomesCurrent) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);
  bool observed = false;
  harness.coordinator->set_phase_hook([&](CoordinatorPhase phase) {
    if (phase == CoordinatorPhase::AfterCommit) {
      observed = true;
    }
  });
  const Result<CommitOutcome> outcome =
      harness.coordinator->evaluate(harness.next_context(), set.id, candidates);
  CRF_CHECK_RESULT(outcome);
  if (!outcome.ok()) {
    return;
  }
  CRF_CHECK(observed);
  CRF_CHECK(outcome.value().committed);
  CRF_CHECK_EQ(outcome.value().batch.batch_outcome, BatchOutcome::AdmissibleCandidatesAvailable);
  CRF_CHECK_EQ(outcome.value().batch.admissible_order.size(), std::size_t{3});
  const Result<CurrentnessReport> currentness = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(currentness);
  CRF_CHECK_EQ(currentness.value().current_results, std::size_t{3});
  harness.coordinator->set_phase_hook({});
}

CRF_TEST(Race, PreciseInvalidationTouchesOnlyDependentResults) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();

  // Two constraint sets: one depends on capability 5, the other on capability 6.
  std::vector<Constraint> first_constraints = {
      with_capabilities(cid(1), ConstraintKind::RequiredCapability, {capid(5)})};
  ConstraintSet first = make_set(setid(20), first_constraints, evidence);
  first.name = "first";
  const Result<ConstraintSet> published_first =
      harness.coordinator->publish_constraint_set(harness.next_context(), first);
  CRF_CHECK_RESULT(published_first);
  CRF_CHECK_RESULT(harness.coordinator->apply_lifecycle(harness.next_context(), setid(20),
                                                       LifecycleEvent::Activate));

  std::vector<Constraint> second_constraints = {
      with_capabilities(cid(1), ConstraintKind::RequiredCapability, {capid(6)})};
  ConstraintSet second = make_set(setid(21), second_constraints, evidence);
  second.name = "second";
  const Result<ConstraintSet> published_second =
      harness.coordinator->publish_constraint_set(harness.next_context(), second);
  CRF_CHECK_RESULT(published_second);
  CRF_CHECK_RESULT(harness.coordinator->apply_lifecycle(harness.next_context(), setid(21),
                                                       LifecycleEvent::Activate));

  PathSpec first_spec;
  first_spec.path = pathid(400);
  first_spec.nodes = {nid(10), nid(11)};
  first_spec.first_link = 4000;
  first_spec.capabilities = {capid(5)};
  const std::vector<CandidatePath> first_candidates = {build_candidate(first_spec, evidence)};

  PathSpec second_spec;
  second_spec.path = pathid(401);
  second_spec.nodes = {nid(10), nid(11)};
  second_spec.first_link = 4010;
  second_spec.capabilities = {capid(6)};
  const std::vector<CandidatePath> second_candidates = {build_candidate(second_spec, evidence)};

  CRF_CHECK_RESULT(harness.coordinator->evaluate(harness.next_context(), setid(20), first_candidates));
  CRF_CHECK_RESULT(harness.coordinator->evaluate(harness.next_context(), setid(21), second_candidates));

  const Result<CurrentnessReport> before_first = harness.coordinator->currentness(setid(20));
  const Result<CurrentnessReport> before_second = harness.coordinator->currentness(setid(21));
  CRF_CHECK_RESULT(before_first);
  CRF_CHECK_RESULT(before_second);
  CRF_CHECK_EQ(before_first.value().current_results, std::size_t{1});
  CRF_CHECK_EQ(before_second.value().current_results, std::size_t{1});

  // A change to capability 5 must invalidate only the evaluations that bound it.
  CRF_CHECK_STATUS(harness.coordinator->invalidate_key(
      harness.next_context(), InvalidationKey{InvalidationKeyKind::Capability, capid(5).value()}));

  const Result<CurrentnessReport> after_first = harness.coordinator->currentness(setid(20));
  const Result<CurrentnessReport> after_second = harness.coordinator->currentness(setid(21));
  CRF_CHECK_RESULT(after_first);
  CRF_CHECK_RESULT(after_second);
  CRF_CHECK_EQ(after_first.value().current_results, std::size_t{0});
  CRF_CHECK_EQ(after_first.value().revalidation_required, std::size_t{1});
  CRF_CHECK_EQ(after_second.value().current_results, std::size_t{1});
  CRF_CHECK_EQ(after_second.value().revalidation_required, std::size_t{0});
  CRF_CHECK_STATUS(harness.coordinator->invalidation_index().validate());
}

CRF_TEST(Race, InvalidatingAnUnrelatedKeyChangesNothing) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);
  CRF_CHECK_RESULT(harness.coordinator->evaluate(harness.next_context(), set.id, candidates));
  const Result<CurrentnessReport> before = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(before);
  CRF_CHECK_EQ(before.value().current_results, std::size_t{3});

  CRF_CHECK_STATUS(harness.coordinator->invalidate_key(
      harness.next_context(), InvalidationKey{InvalidationKeyKind::Node, nid(7777).value()}));
  CRF_CHECK_STATUS(harness.coordinator->invalidate_key(
      harness.next_context(), InvalidationKey{InvalidationKeyKind::Capability, capid(999).value()}));

  const Result<CurrentnessReport> after = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(after);
  CRF_CHECK_EQ(after.value().current_results, std::size_t{3});
  CRF_CHECK_EQ(after.value().revalidation_required, std::size_t{0});
}

CRF_TEST(Race, RevalidationRestoresCurrentResults) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);
  CRF_CHECK_RESULT(harness.coordinator->evaluate(harness.next_context(), set.id, candidates));

  CRF_CHECK_STATUS(harness.coordinator->invalidate_key(
      harness.next_context(), InvalidationKey{InvalidationKeyKind::Node, nid(11).value()}));
  Result<CurrentnessReport> report = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(report);
  CRF_CHECK_EQ(report.value().current_results, std::size_t{0});

  const Result<CommitOutcome> revalidated =
      harness.coordinator->revalidate(harness.next_context(), set.id);
  CRF_CHECK_RESULT(revalidated);
  CRF_CHECK(revalidated.value().committed);
  report = harness.coordinator->currentness(set.id);
  CRF_CHECK_RESULT(report);
  CRF_CHECK_EQ(report.value().current_results, std::size_t{3});
  CRF_CHECK_EQ(report.value().revalidation_required, std::size_t{0});
  CRF_CHECK_EQ(report.value().recovered_unproven, std::size_t{0});
}

CRF_TEST(Race, GenerationsNeverDecrease) {
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const EvidenceRequirements evidence = standard_evidence();
  CRF_CHECK_STATUS(harness.coordinator->advance_family(harness.next_context(),
                                                       EvidenceFamily::Capability, 50));
  const Status lower = harness.coordinator->advance_family(harness.next_context(),
                                                           EvidenceFamily::Capability, 49);
  CRF_CHECK_EQ(lower.code(), ErrorCode::StaleGeneration);
  // Re-stating the current generation is an idempotent no-op, not a decrease.
  const Status equal = harness.coordinator->advance_family(harness.next_context(),
                                                           EvidenceFamily::Capability, 50);
  CRF_CHECK_STATUS(equal);
  CRF_CHECK_EQ(harness.coordinator->evidence_requirements().capability.value(), std::uint64_t{50});
  CRF_CHECK_EQ(evidence.capability.value(), std::uint64_t{5});
}

CRF_TEST(Race, LifecycleChangeDuringEvaluationRejectsTheCompletion) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);
  bool suspended = false;
  harness.coordinator->set_phase_hook([&](CoordinatorPhase phase) {
    if (phase != CoordinatorPhase::AfterDependencySnapshot || suspended) {
      return;
    }
    suspended = true;
    CRF_CHECK_RESULT(harness.coordinator->apply_lifecycle(harness.next_context(), set.id,
                                                         LifecycleEvent::Suspend));
  });
  const Result<CommitOutcome> outcome =
      harness.coordinator->evaluate(harness.next_context(), set.id, candidates);
  CRF_CHECK_RESULT(outcome);
  if (!outcome.ok()) {
    return;
  }
  CRF_CHECK(suspended);
  CRF_CHECK(!outcome.value().committed);
  CRF_CHECK_EQ(outcome.value().rejection_reason, ReasonCode::StaleConstraintSetGeneration);
  harness.coordinator->set_phase_hook({});
}

CRF_TEST(Race, ExactReplayOfAnEvaluationIsIdempotent) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness_result = make_harness();
  CRF_CHECK_RESULT(harness_result);
  if (!harness_result.ok()) {
    return;
  }
  CoordinatorHarness& harness = *harness_result.value();
  const ConstraintSet set = publish(harness);
  const std::vector<CandidatePath> candidates = population(evidence);
  const AuthorityContext context = harness.next_context();
  const Result<CommitOutcome> first = harness.coordinator->evaluate(context, set.id, candidates);
  CRF_CHECK_RESULT(first);
  CRF_CHECK(first.value().committed);
  const std::size_t stored = harness.coordinator->stored_evaluation_count();

  // The same attempt identity and the same payload: nothing advances.
  const Result<CommitOutcome> replay = harness.coordinator->evaluate(context, set.id, candidates);
  CRF_CHECK_RESULT(replay);
  CRF_CHECK(replay.value().committed);
  CRF_CHECK_EQ(harness.coordinator->stored_evaluation_count(), stored);

  // The same attempt identity with a different payload is a conflict.
  const std::vector<CandidatePath> other = {candidates.front()};
  const Result<CommitOutcome> conflict = harness.coordinator->evaluate(context, set.id, other);
  CRF_CHECK_EQ(conflict.code(), ErrorCode::MutationAttemptConflict);
  CRF_CHECK_EQ(harness.coordinator->stored_evaluation_count(), stored);
}
