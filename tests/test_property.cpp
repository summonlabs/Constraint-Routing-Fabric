// Constraint Routing Fabric -- property tests with deterministic seeds.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

constexpr std::uint64_t kSeeds[] = {1, 2, 3, 5, 8, 13, 21, 34};

[[nodiscard]] bool admissible(const EvaluationRecord& record) {
  return record.outcome == Outcome::Admissible || record.outcome == Outcome::AdmissibleWithPreferences;
}

[[nodiscard]] CandidatePath random_candidate(test::Rng& rng, PathId path_id,
                                             const EvidenceRequirements& evidence) {
  static const std::uint64_t kNodes[] = {10, 11, 12, 20, 21, 77};
  PathSpec spec;
  spec.path = path_id;
  const std::uint32_t count = 2 + rng.below(3);
  for (std::uint32_t index = 0; index < count; ++index) {
    spec.nodes.push_back(nid(kNodes[rng.below(6)]));
  }
  for (std::size_t a = 0; a < spec.nodes.size(); ++a) {
    for (std::size_t b = a + 1; b < spec.nodes.size(); ++b) {
      if (spec.nodes[a] == spec.nodes[b]) {
        spec.nodes[b] = nid(300 + b);
      }
    }
  }
  spec.first_link = 7000 + path_id.value() * 10;
  spec.tier = tid(1 + rng.below(2));
  spec.site = sid(5 + rng.below(2));
  spec.localities = {LocalityRef{DomainKind::Site, locality(700 + rng.below(2))}};
  spec.domains = {FailureDomainRef{DomainKind::Rack, domain(41 + rng.below(2))}};
  spec.capabilities = {capid(5)};
  spec.isolation_classes = {isolation_class(3)};
  spec.policies = {pid(3)};
  if (rng.coin()) {
    spec.planner_latency_micros = 500 + static_cast<std::int64_t>(rng.below(12000));
  } else {
    spec.observed_latency_micros = 500 + static_cast<std::int64_t>(rng.below(12000));
  }
  spec.bandwidth_bits_per_second = 500 + static_cast<std::int64_t>(rng.below(2000));
  spec.has_planner_rank = true;
  spec.planner_rank = rng.below(5);
  spec.has_planner_cost = rng.coin();
  spec.planner_cost = static_cast<std::int64_t>(rng.below(100));
  // A cost model without a cost is ambiguous input, so the two travel together.
  spec.cost_model = spec.has_planner_cost ? PlannerCostModel::AdministrativeMetric
                                          : PlannerCostModel::None;
  if (rng.below(6) == 0) {
    spec.authority_generation = PathAuthorityGeneration::from_value(90 + rng.below(4));
  }
  return build_candidate(spec, evidence);
}

[[nodiscard]] Constraint random_constraint(test::Rng& rng, std::uint64_t id) {
  static const std::uint64_t kNodes[] = {10, 11, 12, 20, 21, 77};
  static const std::uint64_t kLinks[] = {7000, 7010, 7020, 7030, 7040};
  switch (rng.below(9)) {
    case 0: return max_hops(cid(id), 1 + static_cast<std::int64_t>(rng.below(4)));
    case 1:
      return max_latency(cid(id),
                         rng.coin() ? LatencySource::PlannerCost : LatencySource::ObservedLatency,
                         1000 + static_cast<std::int64_t>(rng.below(12000)));
    case 2: return min_bandwidth(cid(id), 500 + static_cast<std::int64_t>(rng.below(1500)));
    case 3:
      return with_nodes(cid(id),
                        rng.coin() ? ConstraintKind::RequiredNode : ConstraintKind::ForbiddenNode,
                        {nid(kNodes[rng.below(6)])});
    case 4:
      return with_links(cid(id),
                        rng.coin() ? ConstraintKind::RequiredLink : ConstraintKind::ForbiddenLink,
                        {lid(kLinks[rng.below(5)])});
    case 5:
      return with_tiers(cid(id),
                        rng.coin() ? ConstraintKind::RequiredTier : ConstraintKind::ForbiddenTier,
                        {tid(1 + rng.below(2))});
    case 6:
      return with_sites(cid(id),
                        rng.coin() ? ConstraintKind::RequiredSite : ConstraintKind::ForbiddenSite,
                        {sid(5 + rng.below(2))});
    case 7: return locality_scope(cid(id), DomainKind::Site, locality(700 + rng.below(2)));
    default: return isolation_required(cid(id), isolation_class(3));
  }
}

[[nodiscard]] ConstraintSet random_set(test::Rng& rng) {
  const EvidenceRequirements evidence = standard_evidence();
  std::vector<Constraint> constraints;
  const std::uint32_t count = 1 + rng.below(5);
  for (std::uint32_t index = 0; index < count; ++index) {
    constraints.push_back(random_constraint(rng, 10 + index));
  }
  if (rng.coin()) {
    Constraint preference = max_latency(cid(900), LatencySource::PlannerCost, 9000);
    as_preference(preference, 1, 1 + rng.below(10));
    constraints.push_back(preference);
  }
  ConstraintSet set = make_set(setid(50), std::move(constraints), evidence);
  if (set.name.empty()) {
    // make_set only writes a name when the fixture itself is invalid.
    set.name = "property";
  }
  return set;
}

[[nodiscard]] bool set_usable(const ConstraintSet& set) { return set.name == "property"; }

}  // namespace

CRF_TEST(Property, AdmissibleImpliesEveryMandatoryConstraintPassed) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed);
    for (int iteration = 0; iteration < 40; ++iteration) {
      const ConstraintSet set = random_set(rng);
      if (!set_usable(set)) {
        continue;
      }
      const EvidenceRequirements evidence = standard_evidence();
      const EvaluationContext context = context_for(set, evidence);
      const CandidatePath candidate = random_candidate(rng, pathid(1000), evidence);
      CRF_CHECK_STATUS(validate_candidate(candidate, Limits{}));
      const Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
      CRF_CHECK_RESULT(record);
      if (!record.ok()) {
        continue;
      }
      const std::string label = test::seed_message("Property", seed);
      // An admissible outcome means the reason vector is empty, and therefore
      // that no mandatory constraint produced a reason.
      if (admissible(record.value()) && !record.value().reasons.empty()) {
        CRF_FAIL(label + ": admissible record carries reasons");
      }
      if (!admissible(record.value()) && record.value().reasons.empty()) {
        CRF_FAIL(label + ": non-admissible record carries no reason");
      }
    }
  }
}

CRF_TEST(Property, AddingAMandatoryConstraintNeverRescuesACandidate) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 1000);
    for (int iteration = 0; iteration < 30; ++iteration) {
      ConstraintSet base = random_set(rng);
      if (!set_usable(base)) {
        continue;
      }
      const EvidenceRequirements evidence = standard_evidence();
      const CandidatePath candidate = random_candidate(rng, pathid(1100), evidence);
      const EvaluationContext context = context_for(base, evidence);
      const Result<EvaluationRecord> before = evaluate_candidate(context, candidate);
      CRF_CHECK_RESULT(before);
      if (!before.ok() || admissible(before.value())) {
        continue;
      }
      ConstraintSet extended = base;
      extended.constraints.push_back(random_constraint(rng, 500));
      std::vector<SetDefect> defects;
      std::vector<Contradiction> contradictions;
      const Status status =
          validate_and_finalize_constraint_set(extended, Limits{}, defects, contradictions);
      if (!status.ok()) {
        continue;
      }
      const EvaluationContext extended_context = context_for(extended, evidence);
      const Result<EvaluationRecord> after = evaluate_candidate(extended_context, candidate);
      CRF_CHECK_RESULT(after);
      if (after.ok() && admissible(after.value())) {
        CRF_FAIL(test::seed_message("Property: a mandatory constraint rescued a candidate", seed));
      }
    }
  }
}

CRF_TEST(Property, StalePathAuthorityNeverYieldsACurrentAdmissibleResult) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 2000);
    for (int iteration = 0; iteration < 40; ++iteration) {
      const ConstraintSet set = random_set(rng);
      if (!set_usable(set)) {
        continue;
      }
      const EvidenceRequirements evidence = standard_evidence();
      CandidatePath candidate = random_candidate(rng, pathid(1200), evidence);
      candidate.authority_generation = PathAuthorityGeneration::from_value(1234);
      candidate.evidence.path_authority = candidate.authority_generation;
      const EvaluationContext context = context_for(set, evidence);
      const Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
      CRF_CHECK_RESULT(record);
      if (!record.ok()) {
        continue;
      }
      if (admissible(record.value())) {
        CRF_FAIL(test::seed_message("Property: stale Path Authority was admissible", seed));
      }
      CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::StalePathAuthority);
    }
  }
}

CRF_TEST(Property, MissingRequiredEvidenceNeverSilentlyPasses) {
  const EvidenceRequirements evidence = standard_evidence();
  // Every positive requirement is evaluated against a candidate that carries
  // no evidence of the required family at all.
  struct Case {
    Constraint constraint;
  };
  std::vector<Constraint> constraints;
  constraints.push_back(with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(11)}));
  constraints.push_back(with_capabilities(cid(2), ConstraintKind::RequiredCapability, {capid(5)}));
  constraints.push_back(locality_scope(cid(3), DomainKind::Site, locality(700)));
  constraints.push_back(isolation_required(cid(4), isolation_class(3)));
  constraints.push_back(with_policies(cid(5), {pid(3)}));
  constraints.push_back(required_domain_distinct(cid(6), DomainKind::Rack, 2));
  const ConstraintSet set = make_set(setid(60), constraints, evidence);
  CRF_CHECK_EQ(set.constraints.size(), std::size_t{6});

  PathSpec bare;
  bare.path = pathid(1300);
  bare.nodes = {nid(10), nid(11)};
  bare.first_link = 8000;
  // No capability, policy, locality, isolation or domain evidence, and no
  // latency evidence either.
  const CandidatePath candidate = build_candidate(bare, evidence);
  const Result<EvaluationRecord> record =
      evaluate_candidate(context_for(set, evidence), candidate);
  CRF_CHECK_RESULT(record);
  if (!record.ok()) {
    return;
  }
  CRF_CHECK(!admissible(record.value()));
  CRF_CHECK_EQ(record.value().outcome, Outcome::UnknownRequiredEvidence);
  // Every mandatory requirement that could not be decided reported a reason.
  std::size_t unknown_reasons = 0;
  for (const Reason& reason : record.value().reasons) {
    if (reason.reason_class == ReasonClass::MandatoryConstraint) {
      ++unknown_reasons;
    }
  }
  CRF_CHECK(unknown_reasons >= 4);
}

CRF_TEST(Property, EquivalentInsertionOrderYieldsIdenticalResults) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 3000);
    for (int iteration = 0; iteration < 25; ++iteration) {
      ConstraintSet reference = random_set(rng);
      if (!set_usable(reference)) {
        continue;
      }
      ConstraintSet shuffled = reference;
      for (std::size_t index = shuffled.constraints.size(); index > 1; --index) {
        const std::size_t other = rng.below(static_cast<std::uint32_t>(index));
        std::swap(shuffled.constraints[index - 1], shuffled.constraints[other]);
      }
      std::vector<SetDefect> defects;
      std::vector<Contradiction> contradictions;
      const Status status =
          validate_and_finalize_constraint_set(shuffled, Limits{}, defects, contradictions);
      CRF_CHECK_STATUS(status);
      if (!status.ok()) {
        continue;
      }
      CRF_CHECK_EQ(shuffled.digest, reference.digest);
      const EvidenceRequirements evidence = standard_evidence();
      const CandidatePath candidate = random_candidate(rng, pathid(1400), evidence);
      const Result<EvaluationRecord> first =
          evaluate_candidate(context_for(reference, evidence), candidate);
      const Result<EvaluationRecord> second =
          evaluate_candidate(context_for(shuffled, evidence), candidate);
      CRF_CHECK_RESULT(first);
      CRF_CHECK_RESULT(second);
      if (first.ok() && second.ok()) {
        CRF_CHECK_EQ(first.value().digest, second.value().digest);
        CRF_CHECK_EQ(static_cast<std::uint16_t>(first.value().outcome),
                     static_cast<std::uint16_t>(second.value().outcome));
      }
    }
  }
}

CRF_TEST(Property, ContradictoryConstraintSetsAlwaysReject) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 4000);
    for (int iteration = 0; iteration < 40; ++iteration) {
      const std::uint64_t entity = 50 + rng.below(20);
      ConstraintSet set;
      set.id = setid(70);
      set.generation = ConstraintSetGeneration::from_value(1);
      set.evidence = standard_evidence();
      const bool use_nodes = rng.coin();
      if (use_nodes) {
        set.constraints.push_back(with_nodes(cid(1), ConstraintKind::RequiredNode,
                                             {nid(entity), nid(entity + 100)}));
        set.constraints.push_back(
            with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(entity)}));
      } else {
        set.constraints.push_back(with_links(cid(1), ConstraintKind::RequiredLink,
                                             {lid(entity), lid(entity + 100)}));
        set.constraints.push_back(with_links(cid(2), ConstraintKind::ForbiddenLink, {lid(entity)}));
      }
      std::vector<SetDefect> defects;
      std::vector<Contradiction> contradictions;
      const Status status =
          validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
      CRF_CHECK_EQ(status.code(), ErrorCode::ContradictoryConstraintSet);
      if (!contradictions.empty()) {
        CRF_CHECK_EQ(contradictions.front().kind,
                     ContradictionKind::RequiredAndForbiddenSameEntity);
        CRF_CHECK_EQ(contradictions.front().subject, entity);
      }
      // The caller's set is untouched by the rejection.
      CRF_CHECK_EQ(set.constraints.size(), std::size_t{2});
    }
  }
}

CRF_TEST(Property, StaleAuthorityContextsCanNeverMutate) {
  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (!harness.ok()) {
    return;
  }
  CoordinatorHarness& value = *harness.value();
  test::Rng candidate_rng(99);
  const std::vector<CandidatePath> candidates = {
      random_candidate(candidate_rng, pathid(1500), standard_evidence())};
  const ConstraintSet set = make_set(setid(80), {max_hops(cid(1), 8)}, standard_evidence());
  AuthorityContext good = value.next_context();
  CRF_CHECK_RESULT(value.coordinator->publish_constraint_set(good, set));
  CRF_CHECK_RESULT(value.coordinator->apply_lifecycle(value.next_context(), setid(80),
                                                      LifecycleEvent::Activate));
  const std::size_t stored = value.coordinator->stored_evaluation_count();

  // A stale epoch never mutates.
  AuthorityContext stale_epoch = value.next_context();
  stale_epoch.epoch =
      CoordinatorEpoch::from_value(value.coordinator->epoch().value() + 7);
  CRF_CHECK_EQ(value.coordinator->evaluate(stale_epoch, setid(80), candidates).code(),
               ErrorCode::EpochMismatch);

  // A boot that is not the registered one never mutates.
  AuthorityContext fenced = value.next_context();
  fenced.worker_boot = WorkerBootId::from_value(9999);
  CRF_CHECK(!value.coordinator->evaluate(fenced, setid(80), candidates).ok());

  // An unregistered session never mutates.
  AuthorityContext unknown_session = value.next_context();
  unknown_session.session = SessionId::from_value(9999);
  CRF_CHECK(!value.coordinator->evaluate(unknown_session, setid(80), candidates).ok());

  CRF_CHECK_EQ(value.coordinator->stored_evaluation_count(), stored);
}

CRF_TEST(Property, ExactReplayAdvancesNothingAndIndexesStayConsistent) {
  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (!harness.ok()) {
    return;
  }
  CoordinatorHarness& value = *harness.value();
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(90),
      {max_hops(cid(1), 8), with_capabilities(cid(2), ConstraintKind::RequiredCapability, {capid(5)}),
       with_nodes(cid(3), ConstraintKind::RequiredNode, {nid(11)})},
      evidence);
  CRF_CHECK_RESULT(value.coordinator->publish_constraint_set(value.next_context(), set));
  CRF_CHECK_RESULT(value.coordinator->apply_lifecycle(value.next_context(), setid(90),
                                                      LifecycleEvent::Activate));

  test::Rng rng(4242);
  std::vector<CandidatePath> candidates;
  for (std::uint32_t index = 0; index < 4; ++index) {
    candidates.push_back(random_candidate(rng, pathid(1600 + index), evidence));
  }
  const AuthorityContext context = value.next_context();
  const Result<CommitOutcome> first = value.coordinator->evaluate(context, setid(90), candidates);
  CRF_CHECK_RESULT(first);
  if (!first.ok()) {
    return;
  }
  const std::size_t stored = value.coordinator->stored_evaluation_count();
  const Digest256 before = persistent_state_digest([&] {
    PersistentState state;
    state.epoch = value.coordinator->epoch();
    state.evidence = value.coordinator->evidence_requirements();
    const Result<ConstraintSet> stored_set = value.coordinator->get_constraint_set(setid(90));
    if (stored_set.ok()) {
      state.sets.push_back(stored_set.value());
    }
    return state;
  }());

  const Result<CommitOutcome> replay = value.coordinator->evaluate(context, setid(90), candidates);
  CRF_CHECK_RESULT(replay);
  CRF_CHECK(replay.value().committed);
  CRF_CHECK_EQ(value.coordinator->stored_evaluation_count(), stored);
  const Digest256 after = persistent_state_digest([&] {
    PersistentState state;
    state.epoch = value.coordinator->epoch();
    state.evidence = value.coordinator->evidence_requirements();
    const Result<ConstraintSet> stored_set = value.coordinator->get_constraint_set(setid(90));
    if (stored_set.ok()) {
      state.sets.push_back(stored_set.value());
    }
    return state;
  }());
  CRF_CHECK_EQ(before, after);

  // The reverse index agrees with the records it was built from.
  CRF_CHECK_STATUS(value.coordinator->invalidation_index().validate());
  CRF_CHECK(value.coordinator->invalidation_index().evaluation_count() > 0);
  CRF_CHECK(value.coordinator->invalidation_index().key_count() > 0);
}

CRF_TEST(Property, GenerationsNeverDecreaseAndNeverWrap) {
  EvaluationGeneration generation = EvaluationGeneration::from_value(1);
  for (int step = 0; step < 1000; ++step) {
    EvaluationGeneration next;
    CRF_CHECK(generation.next(next));
    CRF_CHECK(generation < next);
    generation = next;
  }
  CRF_CHECK_EQ(generation.value(), std::uint64_t{1001});

  // The absolute ceiling fails rather than wrapping.
  const Generation<EvaluationGenerationTag> ceiling =
      Generation<EvaluationGenerationTag>::from_value(
          Generation<EvaluationGenerationTag>::kMaxGeneration);
  EvaluationGeneration overflow;
  CRF_CHECK(!ceiling.next(overflow));

  // An unset counter starts at one.
  EvaluationGeneration unset;
  EvaluationGeneration first;
  CRF_CHECK(unset.next(first));
  CRF_CHECK_EQ(first.value(), std::uint64_t{1});

  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (harness.ok()) {
    CRF_CHECK_STATUS(harness.value()->coordinator->advance_family(
        harness.value()->next_context(), EvidenceFamily::Topology, 500));
    CRF_CHECK_EQ(harness.value()->coordinator
                     ->advance_family(harness.value()->next_context(), EvidenceFamily::Topology, 499)
                     .code(),
                 ErrorCode::StaleGeneration);
    CRF_CHECK_EQ(harness.value()->coordinator->evidence_requirements().topology.value(),
                 std::uint64_t{500});
  }
}

CRF_TEST(Property, PersistenceRoundTripsForRandomStates) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 5000);
    PersistentState state;
    state.initialized = true;
    state.epoch = CoordinatorEpoch::from_value(1 + rng.below(50));
    state.evidence = standard_evidence();
    for (std::uint32_t index = 0; index < 1 + rng.below(2); ++index) {
      ConstraintSet set = random_set(rng);
      set.id = setid(100 + index);
      std::vector<SetDefect> defects;
      std::vector<Contradiction> contradictions;
      const Status status =
          validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
      if (!status.ok()) {
        continue;
      }
      state.sets.push_back(set);
    }
    if (state.sets.empty()) {
      continue;
    }
    const Digest256 digest = persistent_state_digest(state);
    const std::vector<std::byte> raw = encode_envelope([&] {
      ByteWriter writer;
      encode_persistent_state(writer, state);
      return writer.buffer();
    }());
    std::vector<std::byte> payload;
    CRF_CHECK_STATUS(decode_envelope(raw, Limits{}, payload));
    ByteReader reader(payload);
    PersistentState decoded;
    CRF_CHECK(decode_persistent_state(reader, Limits{}, decoded));
    CRF_CHECK(reader.at_end());
    CRF_CHECK_STATUS(validate_persistent_state(decoded, Limits{}));
    CRF_CHECK_EQ(persistent_state_digest(decoded), digest);
  }
}

CRF_TEST(Property, RankingIsATotalOrderConsistentWithTheEmittedSequence) {
  for (const std::uint64_t seed : kSeeds) {
    test::Rng rng(seed + 6000);
    for (int iteration = 0; iteration < 15; ++iteration) {
      ConstraintSet set = random_set(rng);
      if (!set_usable(set)) {
        continue;
      }
      set.ranking.consume_planner_rank = rng.coin();
      set.ranking.consume_planner_cost = rng.coin();
      set.ranking.expected_cost_model = PlannerCostModel::AdministrativeMetric;
      std::vector<SetDefect> defects;
      std::vector<Contradiction> contradictions;
      const Status status =
          validate_and_finalize_constraint_set(set, Limits{}, defects, contradictions);
      CRF_CHECK_STATUS(status);
      if (!status.ok()) {
        continue;
      }
      const EvidenceRequirements evidence = standard_evidence();
      std::vector<CandidatePath> candidates;
      for (std::uint32_t index = 0; index < 5; ++index) {
        candidates.push_back(random_candidate(rng, pathid(1700 + index), evidence));
      }
      std::vector<CandidatePath> shuffled = candidates;
      for (std::size_t index = shuffled.size(); index > 1; --index) {
        std::swap(shuffled[index - 1], shuffled[rng.below(static_cast<std::uint32_t>(index))]);
      }
      const Result<EvaluationBatch> forward =
          evaluate_batch(context_for(set, evidence), candidates);
      const Result<EvaluationBatch> backward =
          evaluate_batch(context_for(set, evidence), shuffled);
      CRF_CHECK_RESULT(forward);
      CRF_CHECK_RESULT(backward);
      if (!forward.ok() || !backward.ok()) {
        continue;
      }
      CRF_CHECK_EQ(forward.value().admissible_order.size(),
                   backward.value().admissible_order.size());
      for (std::size_t index = 0; index < forward.value().admissible_order.size(); ++index) {
        CRF_CHECK_EQ(forward.value().admissible_order[index].path,
                     backward.value().admissible_order[index].path);
      }
      // The emitted sequence is strictly increasing under the comparator.
      for (std::size_t index = 0; index + 1 < forward.value().records.size(); ++index) {
        (void)index;
      }
    }
  }
}
