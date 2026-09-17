// Constraint Routing Fabric -- evaluator semantics and precedence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <string>
#include <vector>

#include "constraint_routing_fabric/evaluator.hpp"
#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;            // NOLINT(google-build-using-namespace)
using namespace crf::fixture;   // NOLINT(google-build-using-namespace)

[[nodiscard]] EvaluationRecord evaluate_one(const ConstraintSet& set, const CandidatePath& candidate,
                                            const EvidenceRequirements& evidence) {
  const EvaluationContext context = context_for(set, evidence);
  Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
  if (!record.ok()) {
    CRF_FAIL(std::string("evaluate_candidate failed: ") + to_string(record.code()));
    return EvaluationRecord{};
  }
  return std::move(record.value());
}

[[nodiscard]] CandidatePath simple_path(PathId id, const EvidenceRequirements& evidence,
                                        std::int64_t latency = 3000) {
  PathSpec spec;
  spec.path = id;
  spec.nodes = {nid(10), nid(11), nid(12)};
  spec.first_link = 1000 + id.value() * 10;
  spec.planner_latency_micros = latency;
  spec.bandwidth_bits_per_second = 10000000000LL;
  return build_candidate(spec, evidence);
}

[[nodiscard]] bool has_reason(const EvaluationRecord& record, ReasonCode code) {
  return std::any_of(record.reasons.begin(), record.reasons.end(),
                     [code](const Reason& reason) { return reason.code == code; });
}

}  // namespace

CRF_TEST(Evaluator, DefaultDenyWithoutAuthorityContext) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 4)}, evidence);
  EvaluationContext context = context_for(set, evidence);
  context.authority_verified = false;
  context.provenance = Provenance{};
  const Result<EvaluationRecord> record = evaluate_candidate(context, simple_path(pathid(1), evidence));
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::Unauthorized);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::MissingAuthorityContext);
}

CRF_TEST(Evaluator, OutcomeIsNeverBooleanAndAdmissibleImpliesAllMandatoryPassed) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1),
      {max_hops(cid(1), 4), max_latency(cid(2), LatencySource::PlannerCost, 9000),
       with_nodes(cid(3), ConstraintKind::RequiredNode, {nid(11)}),
       with_links(cid(4), ConstraintKind::RequiredLink, {lid(1011)})},
      evidence);
  const EvaluationRecord record = evaluate_one(set, simple_path(pathid(1), evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::None);
  CRF_CHECK(record.reasons.empty());
  CRF_CHECK_EQ(record.set_id, setid(1));
  CRF_CHECK_EQ(record.set_generation, set.generation);
  CRF_CHECK_EQ(record.authority_generation, evidence.path_authority);
  CRF_CHECK((record.consulted & family_bit(EvidenceFamily::Topology)) != 0);
  CRF_CHECK(!record.digest.is_zero());
}

CRF_TEST(Evaluator, MandatoryFailuresAreReportedWithExactConstraintIdentity) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1),
      {max_hops(cid(1), 1), with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(11)})},
      evidence);
  const EvaluationRecord record = evaluate_one(set, simple_path(pathid(1), evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(static_cast<std::size_t>(record.reasons.size()), std::size_t{2});
  // Canonical constraint order sorts by kind first, so ForbiddenNode (kind 4)
  // precedes MaxHopCount (kind 18) regardless of declaration order.
  CRF_CHECK_EQ(record.reasons[0].constraint, cid(2));
  CRF_CHECK_EQ(record.reasons[0].code, ReasonCode::ForbiddenNodePresent);
  CRF_CHECK_EQ(record.reasons[0].subject, nid(11).value());
  CRF_CHECK_EQ(record.reasons[0].constraint_ordinal, std::uint32_t{0});
  CRF_CHECK_EQ(record.reasons[1].constraint, cid(1));
  CRF_CHECK_EQ(record.reasons[1].code, ReasonCode::MaxHopCountExceeded);
  CRF_CHECK_EQ(record.reasons[1].constraint_ordinal, std::uint32_t{1});
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::ForbiddenNodePresent);
}

CRF_TEST(Evaluator, PrimaryReasonIsIndependentOfConstraintInsertionOrder) {
  const EvidenceRequirements evidence = standard_evidence();
  const std::vector<Constraint> forward = {
      max_hops(cid(1), 1), with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(11)}),
      max_latency(cid(3), LatencySource::PlannerCost, 10)};
  std::vector<Constraint> reverse(forward.rbegin(), forward.rend());
  const ConstraintSet a = make_set(setid(1), forward, evidence);
  const ConstraintSet b = make_set(setid(1), reverse, evidence);
  CRF_CHECK_EQ(a.digest, b.digest);
  const EvaluationRecord first = evaluate_one(a, simple_path(pathid(1), evidence), evidence);
  const EvaluationRecord second = evaluate_one(b, simple_path(pathid(1), evidence), evidence);
  CRF_CHECK_EQ(first.primary_reason, second.primary_reason);
  CRF_CHECK_EQ(first.digest, second.digest);
  CRF_CHECK_EQ(static_cast<std::size_t>(first.reasons.size()),
               static_cast<std::size_t>(second.reasons.size()));
}

CRF_TEST(Evaluator, PrecedenceIsClassOrderedNotCodeOrdered) {
  const EvidenceRequirements evidence = standard_evidence();
  // A stale Path Authority outranks a hard constraint failure even though the
  // hard failure carries the higher reason code.
  const ConstraintSet set = make_set(
      setid(1), {with_nodes(cid(1), ConstraintKind::ForbiddenNode, {nid(11)})}, evidence);
  CandidatePath candidate = simple_path(pathid(1), evidence);
  candidate.authority_generation = PathAuthorityGeneration::from_value(99);
  candidate.evidence.path_authority = PathAuthorityGeneration::from_value(99);
  const EvaluationRecord record = evaluate_one(set, candidate, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::StalePathAuthority);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::StalePathAuthority);
}

CRF_TEST(Evaluator, PathAuthorityVerdictsAreNeverOverridden) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 8)}, evidence);

  CandidatePath rejected = simple_path(pathid(1), evidence);
  rejected.authority_verdict = PathAuthorityVerdict::Rejected;
  const EvaluationRecord rejected_record = evaluate_one(set, rejected, evidence);
  CRF_CHECK_EQ(rejected_record.outcome, Outcome::Unauthorized);
  CRF_CHECK_EQ(rejected_record.primary_reason, ReasonCode::PathNotLegal);

  CandidatePath unevaluated = simple_path(pathid(2), evidence);
  unevaluated.authority_verdict = PathAuthorityVerdict::NotEvaluated;
  const EvaluationRecord unevaluated_record = evaluate_one(set, unevaluated, evidence);
  CRF_CHECK_EQ(unevaluated_record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(unevaluated_record.primary_reason, ReasonCode::PathAuthorityNotEvaluated);
}

CRF_TEST(Evaluator, LifecycleStatesMapToExplicitOutcomes) {
  const EvidenceRequirements evidence = standard_evidence();
  const CandidatePath candidate = simple_path(pathid(1), evidence);
  const struct {
    ConstraintSetState state;
    Outcome outcome;
    ReasonCode reason;
  } cases[] = {
      {ConstraintSetState::Declared, Outcome::StaleConstraintSet, ReasonCode::ConstraintSetNotActive},
      {ConstraintSetState::Active, Outcome::Admissible, ReasonCode::None},
      {ConstraintSetState::Suspended, Outcome::StaleConstraintSet, ReasonCode::ConstraintSetSuspended},
      {ConstraintSetState::RevalidationRequired, Outcome::RevalidationRequired,
       ReasonCode::ConstraintSetRevalidationRequired},
      {ConstraintSetState::Revoked, Outcome::Unauthorized, ReasonCode::ConstraintSetRevoked},
      {ConstraintSetState::Superseded, Outcome::StaleConstraintSet, ReasonCode::ConstraintSetSuperseded},
      {ConstraintSetState::Retired, Outcome::StaleConstraintSet, ReasonCode::ConstraintSetRetired},
  };
  for (const auto& entry : cases) {
    ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 8)}, evidence);
    set.state = entry.state;
    const EvaluationRecord record = evaluate_one(set, candidate, evidence);
    CRF_CHECK_EQ(record.outcome, entry.outcome);
    CRF_CHECK_EQ(record.primary_reason, entry.reason);
  }
}

CRF_TEST(Evaluator, StaleConstraintSetGenerationIsReported) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 8)}, evidence);
  EvaluationContext context = context_for(set, evidence);
  context.requested_set_generation = ConstraintSetGeneration::from_value(4);
  const Result<EvaluationRecord> record = evaluate_candidate(context, simple_path(pathid(1), evidence));
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::StaleConstraintSet);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::StaleConstraintSetGeneration);
}

CRF_TEST(Evaluator, StaleEvidenceIsReportedPerFamily) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1),
      {with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(11)}),
       with_capabilities(cid(2), ConstraintKind::RequiredCapability, {capid(5)})},
      evidence);
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11), nid(12)};
  spec.first_link = 1000;
  spec.planner_latency_micros = 3000;
  spec.capabilities = {capid(5)};
  CandidatePath candidate = build_candidate(spec, evidence);

  EvidenceRequirements advanced = evidence;
  advanced.topology = TopologyGeneration::from_value(4);
  EvaluationRecord record = evaluate_one(set, candidate, advanced);
  CRF_CHECK_EQ(record.outcome, Outcome::StaleEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::StaleTopologyEvidence);

  EvidenceRequirements advanced_capability = evidence;
  advanced_capability.capability = CapabilityGeneration::from_value(6);
  record = evaluate_one(set, candidate, advanced_capability);
  CRF_CHECK_EQ(record.outcome, Outcome::StaleEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::StaleCapabilityEvidence);

  // A family the constraint set never consults must not invalidate anything.
  EvidenceRequirements unrelated = evidence;
  unrelated.policy = PolicyGeneration::from_value(9);
  record = evaluate_one(set, candidate, unrelated);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);
}

CRF_TEST(Evaluator, UnboundEvidenceIsReportedAsNotBound) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(11)})}, evidence);
  EvidenceRequirements unbound = evidence;
  unbound.topology = TopologyGeneration{};
  const EvaluationRecord record = evaluate_one(set, simple_path(pathid(1), evidence), unbound);
  CRF_CHECK_EQ(record.outcome, Outcome::StaleEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::EvidenceNotBound);
}

CRF_TEST(Evaluator, EvidenceAgeBoundIsEnforced) {
  const EvidenceRequirements evidence = standard_evidence();
  ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 8)}, evidence);
  EvidenceRequirements aged = evidence;
  aged.max_evidence_age_ticks = 10;
  CandidatePath candidate = simple_path(pathid(1), evidence);
  candidate.evidence.captured_tick = 100;
  EvaluationContext context = context_for(set, aged);
  context.now_tick = 105;
  Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::Admissible);

  context.now_tick = 200;
  record = evaluate_candidate(context, candidate);
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(record.value().outcome, Outcome::StaleEvidence);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::EvidenceAgeExceeded);
}

CRF_TEST(Evaluator, ModelledAndObservedLatencyAreNeverMixed) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {max_latency(cid(1), LatencySource::PlannerCost, 9000)}, evidence);
  PathSpec observed_spec;
  observed_spec.path = pathid(1);
  observed_spec.nodes = {nid(10), nid(11)};
  observed_spec.first_link = 1000;
  observed_spec.observed_latency_micros = 100;
  const CandidatePath observed = build_candidate(observed_spec, evidence);
  const EvaluationRecord record = evaluate_one(set, observed, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::LatencyEvidenceUnavailable);

  PathSpec planner_spec;
  planner_spec.path = pathid(2);
  planner_spec.nodes = {nid(10), nid(11)};
  planner_spec.first_link = 1010;
  planner_spec.planner_latency_micros = 100;
  const CandidatePath planner = build_candidate(planner_spec, evidence);
  const ConstraintSet observed_set = make_set(
      setid(2), {max_latency(cid(1), LatencySource::ObservedLatency, 9000)}, evidence);
  const EvaluationRecord reverse = evaluate_one(observed_set, planner, evidence);
  CRF_CHECK_EQ(reverse.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(reverse.primary_reason, ReasonCode::LatencyEvidenceUnavailable);
}

CRF_TEST(Evaluator, BandwidthCapabilityIsEvidenceNotReservation) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {min_bandwidth(cid(1), 1000)}, evidence);

  PathSpec below;
  below.path = pathid(1);
  below.nodes = {nid(10), nid(11)};
  below.first_link = 1000;
  below.bandwidth_bits_per_second = 999;
  EvaluationRecord record = evaluate_one(set, build_candidate(below, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::MinBandwidthCapabilityNotMet);
  CRF_CHECK_EQ(record.reasons[0].actual, std::uint64_t{999});
  CRF_CHECK_EQ(record.reasons[0].expected, std::uint64_t{1000});

  PathSpec unknown = below;
  unknown.path = pathid(2);
  unknown.first_link = 1100;
  unknown.bandwidth_bits_per_second = 0;
  record = evaluate_one(set, build_candidate(unknown, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::BandwidthCapabilityUnavailable);

  PathSpec above = below;
  above.path = pathid(3);
  above.first_link = 1200;
  above.bandwidth_bits_per_second = 1000;
  record = evaluate_one(set, build_candidate(above, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);
}

CRF_TEST(Evaluator, LocalityUsesAuthoritativeMembershipOnly) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {locality_scope(cid(1), DomainKind::Site, locality(700))}, evidence);

  PathSpec inside;
  inside.path = pathid(1);
  inside.nodes = {nid(10), nid(11)};
  inside.first_link = 1000;
  inside.localities = {LocalityRef{DomainKind::Site, locality(700)}};
  EvaluationRecord record = evaluate_one(set, build_candidate(inside, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);

  PathSpec outside = inside;
  outside.path = pathid(2);
  outside.first_link = 1100;
  outside.localities = {LocalityRef{DomainKind::Site, locality(701)}};
  record = evaluate_one(set, build_candidate(outside, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::LocalityScopeViolated);

  PathSpec unknown = inside;
  unknown.path = pathid(3);
  unknown.first_link = 1200;
  unknown.localities.clear();
  record = evaluate_one(set, build_candidate(unknown, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::LocalityEvidenceUnavailable);
}

CRF_TEST(Evaluator, IsolationRequiresPositiveProof) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {isolation_required(cid(1), isolation_class(3))}, evidence);

  PathSpec proven;
  proven.path = pathid(1);
  proven.nodes = {nid(10), nid(11)};
  proven.first_link = 1000;
  proven.isolation_classes = {isolation_class(3)};
  EvaluationRecord record = evaluate_one(set, build_candidate(proven, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);

  PathSpec other = proven;
  other.path = pathid(2);
  other.first_link = 1100;
  other.isolation_classes = {isolation_class(4)};
  record = evaluate_one(set, build_candidate(other, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::IsolationClassNotProven);

  PathSpec none = proven;
  none.path = pathid(3);
  none.first_link = 1200;
  none.isolation_classes.clear();
  record = evaluate_one(set, build_candidate(none, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::IsolationEvidenceUnavailable);
}

CRF_TEST(Evaluator, FailureDomainRelations) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet distinct = make_set(
      setid(1), {required_domain_distinct(cid(1), DomainKind::Rack, 2)}, evidence);

  PathSpec spread;
  spread.path = pathid(1);
  spread.nodes = {nid(10), nid(11), nid(12)};
  spread.first_link = 1000;
  spread.domains = {FailureDomainRef{DomainKind::Rack, domain(41)}};
  EvaluationRecord record = evaluate_one(distinct, build_candidate(spread, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::RequiredFailureDomainRelationNotMet);

  PathSpec incomplete = spread;
  incomplete.path = pathid(2);
  incomplete.first_link = 1100;
  incomplete.domains.clear();
  record = evaluate_one(distinct, build_candidate(incomplete, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::FailureDomainEvidenceUnavailable);

  const ConstraintSet shared = make_set(
      setid(2), {forbidden_domain_shared(cid(1), DomainKind::Rack)}, evidence);
  record = evaluate_one(shared, build_candidate(spread, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::ForbiddenFailureDomainRelationMet);

  // A negative constraint may explicitly permit unknown evidence to be treated
  // as "the forbidden relation is not proven".
  Constraint permissive = forbidden_domain_shared(cid(1), DomainKind::Rack);
  permissive.unknown_policy = UnknownPolicy::PermitUnknownNegative;
  const ConstraintSet permissive_set = make_set(setid(3), {permissive}, evidence);
  record = evaluate_one(permissive_set, build_candidate(incomplete, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::Admissible);
}

CRF_TEST(Evaluator, RequiredAndForbiddenTierAndSite) {
  const EvidenceRequirements evidence = standard_evidence();
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11)};
  spec.first_link = 1000;
  spec.tier = tid(2);
  spec.site = sid(5);
  const CandidatePath candidate = build_candidate(spec, evidence);

  const ConstraintSet ok = make_set(
      setid(1), {with_tiers(cid(1), ConstraintKind::RequiredTier, {tid(1), tid(2)}),
                 with_sites(cid(2), ConstraintKind::RequiredSite, {sid(5)}),
                 with_tiers(cid(3), ConstraintKind::ForbiddenTier, {tid(9)}),
                 with_sites(cid(4), ConstraintKind::ForbiddenSite, {sid(6)})},
      evidence);
  CRF_CHECK_EQ(evaluate_one(ok, candidate, evidence).outcome, Outcome::Admissible);

  const ConstraintSet tier_fail = make_set(
      setid(2), {with_tiers(cid(1), ConstraintKind::RequiredTier, {tid(1)})}, evidence);
  CRF_CHECK_EQ(evaluate_one(tier_fail, candidate, evidence).primary_reason,
               ReasonCode::RequiredTierNotMet);

  const ConstraintSet site_fail = make_set(
      setid(3), {with_sites(cid(1), ConstraintKind::RequiredSite, {sid(6)})}, evidence);
  CRF_CHECK_EQ(evaluate_one(site_fail, candidate, evidence).primary_reason,
               ReasonCode::RequiredSiteNotMet);

  const ConstraintSet tier_forbidden = make_set(
      setid(4), {with_tiers(cid(1), ConstraintKind::ForbiddenTier, {tid(2)})}, evidence);
  CRF_CHECK_EQ(evaluate_one(tier_forbidden, candidate, evidence).primary_reason,
               ReasonCode::ForbiddenTierPresent);

  const ConstraintSet site_forbidden = make_set(
      setid(5), {with_sites(cid(1), ConstraintKind::ForbiddenSite, {sid(5)})}, evidence);
  CRF_CHECK_EQ(evaluate_one(site_forbidden, candidate, evidence).primary_reason,
               ReasonCode::ForbiddenSitePresent);

  PathSpec unknown_spec = spec;
  unknown_spec.tier = TierId{};
  unknown_spec.site = SiteId{};
  unknown_spec.path = pathid(2);
  const CandidatePath unknown = build_candidate(unknown_spec, evidence);
  CRF_CHECK_EQ(evaluate_one(tier_fail, unknown, evidence).primary_reason,
               ReasonCode::TierEvidenceUnavailable);
  CRF_CHECK_EQ(evaluate_one(site_fail, unknown, evidence).primary_reason,
               ReasonCode::SiteEvidenceUnavailable);
}

CRF_TEST(Evaluator, CapabilityConstraints) {
  const EvidenceRequirements evidence = standard_evidence();
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11)};
  spec.first_link = 1000;
  spec.capabilities = {capid(5)};
  const CandidatePath candidate = build_candidate(spec, evidence);

  const ConstraintSet required_ok = make_set(
      setid(1), {with_capabilities(cid(1), ConstraintKind::RequiredCapability, {capid(5)})},
      evidence);
  CRF_CHECK_EQ(evaluate_one(required_ok, candidate, evidence).outcome, Outcome::Admissible);

  const ConstraintSet required_missing = make_set(
      setid(2), {with_capabilities(cid(1), ConstraintKind::RequiredCapability, {capid(6)})},
      evidence);
  CRF_CHECK_EQ(evaluate_one(required_missing, candidate, evidence).outcome,
               Outcome::UnknownRequiredEvidence);

  const ConstraintSet forbidden_present = make_set(
      setid(3), {with_capabilities(cid(1), ConstraintKind::ForbiddenCapability, {capid(5)})},
      evidence);
  EvaluationRecord record = evaluate_one(forbidden_present, candidate, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::ForbiddenCapabilityPresent);

  // Absence of a capability record is not proof of absence under fail-closed.
  Constraint allowance = with_capabilities(cid(1), ConstraintKind::ForbiddenCapability, {capid(6)});
  const ConstraintSet strict = make_set(setid(4), {allowance}, evidence);
  record = evaluate_one(strict, candidate, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::CapabilityEvidenceUnavailable);

  allowance.unknown_policy = UnknownPolicy::PermitUnknownNegative;
  const ConstraintSet permissive = make_set(setid(5), {allowance}, evidence);
  CRF_CHECK_EQ(evaluate_one(permissive, candidate, evidence).outcome, Outcome::Admissible);
}

CRF_TEST(Evaluator, AdministrativePolicyBindsAnExactGeneration) {
  const EvidenceRequirements evidence = standard_evidence();
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = {nid(10), nid(11)};
  spec.first_link = 1000;
  spec.policies = {pid(3)};
  const CandidatePath candidate = build_candidate(spec, evidence);

  const ConstraintSet satisfied = make_set(
      setid(1), {with_policies(cid(1), {pid(3)})}, evidence);
  CRF_CHECK_EQ(evaluate_one(satisfied, candidate, evidence).outcome, Outcome::Admissible);

  const ConstraintSet missing = make_set(setid(2), {with_policies(cid(1), {pid(4)})}, evidence);
  EvaluationRecord record = evaluate_one(missing, candidate, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::AdministrativePolicyNotSatisfied);

  CandidatePath stale = candidate;
  stale.policies[0].generation = PolicyGeneration::from_value(6);
  record = evaluate_one(satisfied, stale, evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::UnknownRequiredEvidence);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::PolicyEvidenceUnavailable);
}

CRF_TEST(Evaluator, PreferenceNeverRescuesAHardFailure) {
  const EvidenceRequirements evidence = standard_evidence();
  Constraint preference = max_latency(cid(1), LatencySource::PlannerCost, 100000);
  as_preference(preference, 1, 1000);
  const ConstraintSet set = make_set(
      setid(1),
      {with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(11)}), preference}, evidence);

  PathSpec fast;
  fast.path = pathid(1);
  fast.nodes = {nid(10), nid(11)};
  fast.first_link = 1000;
  fast.planner_latency_micros = 10;
  EvaluationRecord record = evaluate_one(set, build_candidate(fast, evidence), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::HardConstraintFailed);
  CRF_CHECK_EQ(record.primary_reason, ReasonCode::ForbiddenNodePresent);
  CRF_CHECK(record.preferences.empty());
}

CRF_TEST(Evaluator, PreferencesProduceAdmissibleWithPreferencesAndMargins) {
  const EvidenceRequirements evidence = standard_evidence();
  Constraint preference = max_latency(cid(1), LatencySource::PlannerCost, 5000);
  as_preference(preference, 1, 7);
  const ConstraintSet set = make_set(setid(1), {preference}, evidence);
  const EvaluationRecord record = evaluate_one(set, simple_path(pathid(1), evidence, 4000), evidence);
  CRF_CHECK_EQ(record.outcome, Outcome::AdmissibleWithPreferences);
  CRF_CHECK_EQ(static_cast<std::size_t>(record.preferences.size()), std::size_t{1});
  CRF_CHECK(record.preferences[0].satisfied);
  CRF_CHECK_EQ(record.preferences[0].margin, std::int64_t{1000});
  CRF_CHECK_EQ(record.preferences[0].weight, std::uint32_t{7});
}

CRF_TEST(Evaluator, BatchRejectsOversizedAndDuplicatePopulations) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(setid(1), {max_hops(cid(1), 8)}, evidence);
  Limits limits;
  limits.max_candidates_per_evaluation = 2;
  limits.max_batch_size = 1;
  EvaluationContext context = context_for(set, evidence);
  context.limits = &limits;

  const std::vector<CandidatePath> three = {simple_path(pathid(1), evidence),
                                            simple_path(pathid(2), evidence),
                                            simple_path(pathid(3), evidence)};
  Result<EvaluationBatch> batch = evaluate_batch(context, three);
  CRF_CHECK_RESULT(batch);
  CRF_CHECK_EQ(batch.value().batch_outcome, BatchOutcome::BatchRejected);
  CRF_CHECK_EQ(batch.value().primary_batch_reason, ReasonCode::TooManyCandidates);

  Limits two;
  two.max_candidates_per_evaluation = 4;
  two.max_batch_size = 2;
  context.limits = &two;
  batch = evaluate_batch(context, three);
  CRF_CHECK_RESULT(batch);
  CRF_CHECK_EQ(batch.value().batch_outcome, BatchOutcome::BatchRejected);
  CRF_CHECK_EQ(batch.value().primary_batch_reason, ReasonCode::BatchTooLarge);

  Limits four;
  four.max_candidates_per_evaluation = 4;
  four.max_batch_size = 4;
  context.limits = &four;
  CandidatePath conflicting = simple_path(pathid(1), evidence, 9999);
  const std::vector<CandidatePath> duplicates = {simple_path(pathid(1), evidence), conflicting};
  batch = evaluate_batch(context, duplicates);
  CRF_CHECK_RESULT(batch);
  CRF_CHECK_EQ(batch.value().batch_outcome, BatchOutcome::BatchRejected);
  CRF_CHECK_EQ(batch.value().primary_batch_reason, ReasonCode::MalformedCandidate);
}

CRF_TEST(Evaluator, BatchOrderIsIndependentOfArrivalOrder) {
  const EvidenceRequirements evidence = standard_evidence();
  Constraint preference = max_latency(cid(1), LatencySource::PlannerCost, 8000);
  as_preference(preference, 1, 3);
  const ConstraintSet set = make_set(
      setid(1), {max_latency(cid(2), LatencySource::PlannerCost, 20000), preference}, evidence);
  EvaluationContext context = context_for(set, evidence);

  const std::vector<CandidatePath> forward = {simple_path(pathid(1), evidence, 7000),
                                              simple_path(pathid(2), evidence, 6000),
                                              simple_path(pathid(3), evidence, 5000)};
  std::vector<CandidatePath> reverse(forward.rbegin(), forward.rend());
  Result<EvaluationBatch> a = evaluate_batch(context, forward);
  Result<EvaluationBatch> b = evaluate_batch(context, reverse);
  CRF_CHECK_RESULT(a);
  CRF_CHECK_RESULT(b);
  CRF_CHECK_EQ(a.value().admissible_order.size(), b.value().admissible_order.size());
  for (std::size_t index = 0; index < a.value().admissible_order.size(); ++index) {
    CRF_CHECK_EQ(a.value().admissible_order[index].path, b.value().admissible_order[index].path);
    CRF_CHECK_EQ(a.value().records[index].digest, b.value().records[index].digest);
  }
  // The best preference margin ranks first: path 3 is closest to the bound.
  CRF_CHECK_EQ(a.value().admissible_order.front().path, pathid(3));
}

CRF_TEST(Evaluator, QueryWithoutAdmissibleCandidateReportsNoAdmissibleCandidate) {
  const EvidenceRequirements evidence = standard_evidence();
  const ConstraintSet set = make_set(
      setid(1), {with_nodes(cid(1), ConstraintKind::ForbiddenNode, {nid(11), nid(21)})}, evidence);
  EvaluationContext context = context_for(set, evidence);
  const std::vector<CandidatePath> candidates = {simple_path(pathid(1), evidence),
                                                 simple_path(pathid(2), evidence)};
  Result<EvaluationBatch> batch = evaluate_batch(context, candidates);
  CRF_CHECK_RESULT(batch);
  CRF_CHECK_EQ(batch.value().batch_outcome, BatchOutcome::NoAdmissibleCandidate);
  CRF_CHECK(!batch.value().has_admissible);
  CRF_CHECK_EQ(batch.value().primary_batch_reason, ReasonCode::ForbiddenNodePresent);
}

CRF_TEST(Evaluator, ExplanationTruncationKeepsThePrimaryReason) {
  const EvidenceRequirements evidence = standard_evidence();
  // Twenty *distinct* forbidden nodes: equivalent duplicates would collapse
  // during canonicalization and only one reason would remain.
  std::vector<Constraint> constraints;
  std::vector<NodeId> nodes;
  for (std::uint64_t index = 0; index < 20; ++index) {
    nodes.push_back(nid(500 + index));
    constraints.push_back(with_nodes(cid(100 + index), ConstraintKind::ForbiddenNode, {nid(500 + index)}));
  }
  const ConstraintSet set = make_set(setid(1), constraints, evidence);
  CRF_CHECK_EQ(set.constraints.size(), std::size_t{20});
  PathSpec spec;
  spec.path = pathid(1);
  spec.nodes = nodes;
  spec.first_link = 2000;
  const CandidatePath candidate = build_candidate(spec, evidence);
  CRF_CHECK_STATUS(validate_candidate(candidate, Limits{}));

  Limits limits;
  limits.max_explanation_reasons = 5;
  EvaluationContext context = context_for(set, evidence);
  context.limits = &limits;
  const Result<EvaluationRecord> record = evaluate_candidate(context, candidate);
  CRF_CHECK_RESULT(record);
  CRF_CHECK_EQ(static_cast<std::size_t>(record.value().reasons.size()), std::size_t{5});
  CRF_CHECK(record.value().reasons_truncated);
  CRF_CHECK_EQ(record.value().primary_reason, ReasonCode::ForbiddenNodePresent);

  // Without truncation the complete reason vector is bounded but complete.
  Limits full;
  full.max_explanation_reasons = 64;
  EvaluationContext complete_context = context_for(set, evidence);
  complete_context.limits = &full;
  const Result<EvaluationRecord> complete = evaluate_candidate(complete_context, candidate);
  CRF_CHECK_RESULT(complete);
  CRF_CHECK_EQ(static_cast<std::size_t>(complete.value().reasons.size()), std::size_t{20});
  CRF_CHECK(!complete.value().reasons_truncated);
  CRF_CHECK_EQ(complete.value().primary_reason, ReasonCode::ForbiddenNodePresent);
}
