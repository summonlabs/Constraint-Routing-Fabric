// Constraint Routing Fabric -- configured resource-limit enforcement suite.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every bound declared in limits.hpp is exercised here against the exact API
// that consults it, one element over the bound, and asserted to fail with the
// specific rejection rather than a generic one. Three declared bounds have no
// enforcement site anywhere in the library today; those cases pin the observed
// behaviour explicitly instead of pretending the bound bites.
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/coordinator.hpp"
#include "constraint_routing_fabric/evaluator.hpp"
#include "constraint_routing_fabric/invalidation.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/persistence.hpp"
#include "constraint_routing_fabric/protocol.hpp"
#include "constraint_routing_fabric/snapshot.hpp"
#include "constraint_routing_fabric/status.hpp"
#include "constraint_routing_fabric/time.hpp"
#include "test_support.hpp"

namespace {

using ::crf::AuthorityContext;
using ::crf::AuthorityRegistry;
using ::crf::AuthorityScope;
using ::crf::AuthorityScopeMask;
using ::crf::BatchOutcome;
using ::crf::CandidatePath;
using ::crf::CapabilityGeneration;
using ::crf::CapabilityId;
using ::crf::CapabilityRef;
using ::crf::Constraint;
using ::crf::ConstraintGeneration;
using ::crf::ConstraintId;
using ::crf::ConstraintKind;
using ::crf::ConstraintSet;
using ::crf::ConstraintSetGeneration;
using ::crf::ConstraintSetId;
using ::crf::ConstraintSetState;
using ::crf::Contradiction;
using ::crf::Coordinator;
using ::crf::CoordinatorConfig;
using ::crf::CoordinatorEpoch;
using ::crf::Digest256;
using ::crf::DomainKind;
using ::crf::ErrorCode;
using ::crf::EvaluationContext;
using ::crf::FailureDomainId;
using ::crf::FailureDomainRef;
using ::crf::InvalidationIndex;
using ::crf::InvalidationKey;
using ::crf::InvalidationKeyKind;
using ::crf::Limits;
using ::crf::LocalityDomainId;
using ::crf::LocalityRef;
using ::crf::ManualClock;
using ::crf::MutationAttemptId;
using ::crf::NodeId;
using ::crf::Outcome;
using ::crf::PathAuthorityGeneration;
using ::crf::PathId;
using ::crf::PersistentState;
using ::crf::PolicyAttestation;
using ::crf::PolicyGeneration;
using ::crf::PolicyId;
using ::crf::PublisherGrant;
using ::crf::PublisherId;
using ::crf::Reason;
using ::crf::ReasonCode;
using ::crf::ReplayVerdict;
using ::crf::RequestId;
using ::crf::SessionId;
using ::crf::SetDefect;
using ::crf::SiteId;
using ::crf::Status;
using ::crf::TierId;
using ::crf::TopologyGeneration;
using ::crf::WorkerBootId;

// --- rendering helpers ------------------------------------------------------

[[nodiscard]] std::string text(ErrorCode value) { return ::crf::to_string(value); }
[[nodiscard]] std::string text(ReasonCode value) { return ::crf::to_string(value); }
[[nodiscard]] std::string text(BatchOutcome value) { return ::crf::to_string(value); }
[[nodiscard]] std::string text(Outcome value) { return ::crf::to_string(value); }

void check_status_code(const Status& status, ErrorCode expected, const char* file, int line,
                       const char* expression) {
  if (status.code() != expected) {
    ::crf::test::report_failure(file, line,
                                std::string("expected ") + expression + " (actual=" +
                                    text(status.code()) + ", expected=" + text(expected) + ")");
  }
}

template <class T>
void check_result_code(const ::crf::Result<T>& result, ErrorCode expected, const char* file, int line,
                       const char* expression) {
  if (result.code() != expected) {
    ::crf::test::report_failure(file, line,
                                std::string("expected ") + expression + " (actual=" +
                                    text(result.code()) + ", expected=" + text(expected) + ")");
  }
}

// --- builders ---------------------------------------------------------------

[[nodiscard]] Digest256 attempt_digest(std::uint64_t value) {
  return ::crf::digest_of("crf.test.mutation-attempt.v1", [value](::crf::SemanticHasher& hasher) {
    hasher.put_u64(value);
  });
}

[[nodiscard]] Constraint node_constraint(std::uint64_t id_value,
                                         std::initializer_list<std::uint64_t> nodes) {
  Constraint constraint;
  constraint.id = ConstraintId::from_value(id_value);
  constraint.generation = ConstraintGeneration::from_value(1);
  constraint.kind = ConstraintKind::RequiredNode;
  for (const std::uint64_t node : nodes) {
    constraint.nodes.push_back(NodeId::from_value(node));
  }
  return constraint;
}

[[nodiscard]] ConstraintSet make_set(std::uint64_t id_value, std::vector<Constraint> constraints) {
  ConstraintSet set;
  set.id = ConstraintSetId::from_value(id_value);
  set.generation = ConstraintSetGeneration::from_value(1);
  set.name = "limits";
  set.constraints = std::move(constraints);
  return set;
}

/// Canonicalizes with the default limits and fails the calling case when the
/// fixture itself is not a valid definition.
[[nodiscard]] ConstraintSet finalized(ConstraintSet set) {
  std::vector<SetDefect> defects;
  const Status status = ::crf::canonicalize_constraint_set(set, Limits{}, defects);
  CRF_CHECK(status.ok());
  return set;
}

[[nodiscard]] ConstraintSet finalized_set(std::uint64_t set_id, std::uint64_t node) {
  return finalized(make_set(set_id, {node_constraint(1, {node})}));
}

/// \p constraint_count distinct RequiredNode constraints requiring \p count
/// single nodes each.
[[nodiscard]] ConstraintSet finalized_node_set(std::uint32_t constraint_count) {
  std::vector<Constraint> constraints;
  for (std::uint32_t index = 0; index < constraint_count; ++index) {
    constraints.push_back(
        node_constraint(1 + index, {static_cast<std::uint64_t>(1 + index)}));
  }
  return finalized(make_set(1, std::move(constraints)));
}

/// A live, evidence-bound set requiring \p nodes_each nodes on
/// \p constraint_count distinct constraints. None of them appears on the
/// candidate built beside it.
[[nodiscard]] ConstraintSet finalized_failing_set(const Limits& limits,
                                                  std::uint32_t constraint_count,
                                                  std::uint32_t nodes_each) {
  std::vector<Constraint> constraints;
  for (std::uint32_t index = 0; index < constraint_count; ++index) {
    Constraint constraint;
    constraint.id = ConstraintId::from_value(10 + index);
    constraint.generation = ConstraintGeneration::from_value(1);
    constraint.kind = ConstraintKind::RequiredNode;
    for (std::uint32_t item = 0; item < nodes_each; ++item) {
      constraint.nodes.push_back(
          NodeId::from_value(1 + static_cast<std::uint64_t>(index) * 16 + item));
    }
    constraints.push_back(constraint);
  }
  ConstraintSet set = make_set(5, std::move(constraints));
  set.state = ConstraintSetState::Active;
  set.evidence.topology = TopologyGeneration::from_value(1);
  set.evidence.path_authority = PathAuthorityGeneration::from_value(1);
  std::vector<SetDefect> defects;
  const Status status = ::crf::canonicalize_constraint_set(set, limits, defects);
  CRF_CHECK(status.ok());
  return set;
}

[[nodiscard]] CandidatePath make_candidate(std::uint64_t path_id, std::uint32_t node_count) {
  CandidatePath candidate;
  candidate.path = PathId::from_value(path_id);
  candidate.authority_generation = PathAuthorityGeneration::from_value(1);
  candidate.authority_verdict = ::crf::PathAuthorityVerdict::Legal;
  candidate.evidence.path_authority = candidate.authority_generation;
  candidate.evidence.topology = TopologyGeneration::from_value(1);
  candidate.evidence.captured_tick = 10;
  for (std::uint32_t index = 0; index < node_count; ++index) {
    ::crf::NodeFact node;
    node.node = NodeId::from_value(100 + static_cast<std::uint64_t>(index));
    node.tier = TierId::from_value(1);
    node.site = SiteId::from_value(1);
    candidate.nodes.push_back(node);
  }
  for (std::size_t index = 0; index + 1 < candidate.nodes.size(); ++index) {
    ::crf::LinkFact link;
    link.link = ::crf::LinkId::from_value(200 + static_cast<std::uint64_t>(index));
    link.endpoints[0] = candidate.nodes[index].node;
    link.endpoints[1] = candidate.nodes[index + 1].node;
    candidate.links.push_back(link);
  }
  candidate.hop_count = static_cast<std::uint32_t>(candidate.links.size());
  return candidate;
}

[[nodiscard]] EvaluationContext make_context(const ConstraintSet& set, const Limits& limits) {
  EvaluationContext context;
  context.set = &set;
  context.limits = &limits;
  context.current = set.evidence;
  context.now_tick = 100;
  context.generation = ::crf::EvaluationGeneration::from_value(1);
  context.authority_verified = true;
  context.provenance.epoch = CoordinatorEpoch::from_value(1);
  context.provenance.publisher = PublisherId::from_value(1);
  context.provenance.worker_boot = WorkerBootId::from_value(1);
  context.provenance.attempt = MutationAttemptId::from_value(1);
  context.provenance.request = RequestId::from_value(1);
  return context;
}

[[nodiscard]] std::vector<CapabilityRef> capability_refs(std::uint32_t count) {
  std::vector<CapabilityRef> refs;
  for (std::uint32_t index = 0; index < count; ++index) {
    refs.push_back(CapabilityRef{CapabilityId::from_value(1 + static_cast<std::uint64_t>(index)),
                                 CapabilityGeneration::from_value(1)});
  }
  return refs;
}

[[nodiscard]] std::vector<FailureDomainRef> domain_refs(std::uint32_t count) {
  std::vector<FailureDomainRef> refs;
  for (std::uint32_t index = 0; index < count; ++index) {
    refs.push_back(FailureDomainRef{DomainKind::Rack,
                                    FailureDomainId::from_value(1 + static_cast<std::uint64_t>(index))});
  }
  return refs;
}

[[nodiscard]] std::vector<LocalityRef> locality_refs(std::uint32_t count) {
  std::vector<LocalityRef> refs;
  for (std::uint32_t index = 0; index < count; ++index) {
    refs.push_back(LocalityRef{DomainKind::Rack,
                               LocalityDomainId::from_value(1 + static_cast<std::uint64_t>(index))});
  }
  return refs;
}

[[nodiscard]] std::vector<PolicyAttestation> policy_refs(std::uint32_t count) {
  std::vector<PolicyAttestation> refs;
  for (std::uint32_t index = 0; index < count; ++index) {
    refs.push_back(PolicyAttestation{PolicyId::from_value(1 + static_cast<std::uint64_t>(index)),
                                     PolicyGeneration::from_value(1)});
  }
  return refs;
}

[[nodiscard]] bool same_reason(const Reason& a, const Reason& b) {
  return a.code == b.code && a.reason_class == b.reason_class && a.constraint == b.constraint &&
         a.constraint_kind == b.constraint_kind && a.constraint_ordinal == b.constraint_ordinal &&
         a.family == b.family && a.subject_kind == b.subject_kind && a.subject == b.subject &&
         a.expected == b.expected && a.actual == b.actual;
}

[[nodiscard]] std::unique_ptr<Coordinator> open_coordinator(const Limits& limits, ManualClock& clock,
                                                            std::vector<PublisherGrant> grants) {
  CoordinatorConfig config;
  config.limits = limits;
  config.grants = std::move(grants);
  auto coordinator = Coordinator::open_in_memory(config, &clock);
  CRF_CHECK(coordinator.ok());
  if (!coordinator.ok()) {
    return nullptr;
  }
  return std::move(coordinator.value());
}

[[nodiscard]] AuthorityContext authority_context(const Coordinator& coordinator, PublisherId publisher,
                                                 WorkerBootId boot, SessionId session,
                                                 MutationAttemptId attempt) {
  AuthorityContext context;
  context.epoch = coordinator.epoch();
  context.publisher = publisher;
  context.worker_boot = boot;
  context.session = session;
  context.attempt = attempt;
  context.request = RequestId::from_value(1);
  return context;
}

// --- configuration inventory ------------------------------------------------
// One row per field of ::crf::Limits. The row both references the field (so a
// renamed or added field breaks this file) and carries the setter used to prove
// that validate_limits range-checks it.

struct LimitField {
  const char* name;
  std::uint32_t documented_default;
  const char* exercised_by;
  bool consulted_by_library;
  std::uint32_t (*get)(const Limits&);
  void (*set)(Limits&, std::uint32_t);
};

const LimitField kLimitFields[] = {
    {"max_constraint_sets", 64, "Limits.max_constraint_sets", true,
     +[](const Limits& limits) { return limits.max_constraint_sets; },
     +[](Limits& limits, std::uint32_t value) { limits.max_constraint_sets = value; }},
    {"max_constraints_per_set", 256, "Limits.max_constraints_per_set", true,
     +[](const Limits& limits) { return limits.max_constraints_per_set; },
     +[](Limits& limits, std::uint32_t value) { limits.max_constraints_per_set = value; }},
    {"max_entity_refs_per_constraint", 16, "Limits.max_entity_refs_per_constraint", true,
     +[](const Limits& limits) { return limits.max_entity_refs_per_constraint; },
     +[](Limits& limits, std::uint32_t value) { limits.max_entity_refs_per_constraint = value; }},
    {"max_failed_constraints_per_evaluation", 256,
     "Limits.max_failed_constraints_per_evaluation_bounds_distinct_constraints", true,
     +[](const Limits& limits) { return limits.max_failed_constraints_per_evaluation; },
     +[](Limits& limits, std::uint32_t value) {
       limits.max_failed_constraints_per_evaluation = value;
     }},
    {"max_candidates_per_evaluation", 64, "Limits.max_candidates_per_evaluation", true,
     +[](const Limits& limits) { return limits.max_candidates_per_evaluation; },
     +[](Limits& limits, std::uint32_t value) { limits.max_candidates_per_evaluation = value; }},
    {"max_nodes_per_candidate", 64, "Limits.max_nodes_per_candidate", true,
     +[](const Limits& limits) { return limits.max_nodes_per_candidate; },
     +[](Limits& limits, std::uint32_t value) { limits.max_nodes_per_candidate = value; }},
    {"max_links_per_candidate", 64, "Limits.max_links_per_candidate", true,
     +[](const Limits& limits) { return limits.max_links_per_candidate; },
     +[](Limits& limits, std::uint32_t value) { limits.max_links_per_candidate = value; }},
    {"max_capabilities_per_entity", 32, "Limits.max_capabilities_per_entity", true,
     +[](const Limits& limits) { return limits.max_capabilities_per_entity; },
     +[](Limits& limits, std::uint32_t value) { limits.max_capabilities_per_entity = value; }},
    {"max_domains_per_entity", 16, "Limits.max_domains_per_entity", true,
     +[](const Limits& limits) { return limits.max_domains_per_entity; },
     +[](Limits& limits, std::uint32_t value) { limits.max_domains_per_entity = value; }},
    {"max_localities_per_entity", 8, "Limits.max_localities_per_entity", true,
     +[](const Limits& limits) { return limits.max_localities_per_entity; },
     +[](Limits& limits, std::uint32_t value) { limits.max_localities_per_entity = value; }},
    {"max_policies_per_candidate", 32, "Limits.max_policies_per_candidate", true,
     +[](const Limits& limits) { return limits.max_policies_per_candidate; },
     +[](Limits& limits, std::uint32_t value) { limits.max_policies_per_candidate = value; }},
    {"max_explanation_reasons", 64, "Limits.max_explanation_reasons", true,
     +[](const Limits& limits) { return limits.max_explanation_reasons; },
     +[](Limits& limits, std::uint32_t value) { limits.max_explanation_reasons = value; }},
    {"max_batch_size", 64, "Limits.max_batch_size", true,
     +[](const Limits& limits) { return limits.max_batch_size; },
     +[](Limits& limits, std::uint32_t value) { limits.max_batch_size = value; }},
    {"max_publishers", 32, "Limits.max_publishers", true,
     +[](const Limits& limits) { return limits.max_publishers; },
     +[](Limits& limits, std::uint32_t value) { limits.max_publishers = value; }},
    {"max_sessions", 32, "Limits.max_sessions", true,
     +[](const Limits& limits) { return limits.max_sessions; },
     +[](Limits& limits, std::uint32_t value) { limits.max_sessions = value; }},
    {"max_frame_bytes", 1u << 20, "Limits.max_frame_bytes", true,
     +[](const Limits& limits) { return limits.max_frame_bytes; },
     +[](Limits& limits, std::uint32_t value) { limits.max_frame_bytes = value; }},
    {"max_frame_assembly_bytes", 1u << 22, "Limits.max_frame_assembly_bytes", true,
     +[](const Limits& limits) { return limits.max_frame_assembly_bytes; },
     +[](Limits& limits, std::uint32_t value) { limits.max_frame_assembly_bytes = value; }},
    {"max_persistence_record_bytes", 1u << 24, "Limits.max_persistence_record_bytes", true,
     +[](const Limits& limits) { return limits.max_persistence_record_bytes; },
     +[](Limits& limits, std::uint32_t value) { limits.max_persistence_record_bytes = value; }},
    {"max_evaluations_retained", 1024, "Limits.max_evaluations_retained", true,
     +[](const Limits& limits) { return limits.max_evaluations_retained; },
     +[](Limits& limits, std::uint32_t value) { limits.max_evaluations_retained = value; }},
    {"max_fenced_boots", 256, "Limits.max_fenced_boots", true,
     +[](const Limits& limits) { return limits.max_fenced_boots; },
     +[](Limits& limits, std::uint32_t value) { limits.max_fenced_boots = value; }},
    {"max_mutation_attempts", 256, "Limits.max_mutation_attempts", true,
     +[](const Limits& limits) { return limits.max_mutation_attempts; },
     +[](Limits& limits, std::uint32_t value) { limits.max_mutation_attempts = value; }},
    {"max_name_bytes", 128, "Limits.max_name_bytes", true,
     +[](const Limits& limits) { return limits.max_name_bytes; },
     +[](Limits& limits, std::uint32_t value) { limits.max_name_bytes = value; }},
    {"max_detail_bytes", 512, "Limits.max_detail_bytes", true,
     +[](const Limits& limits) { return limits.max_detail_bytes; },
     +[](Limits& limits, std::uint32_t value) { limits.max_detail_bytes = value; }},
    {"max_decoded_count", 1u << 24, "Limits.max_decoded_count", true,
     +[](const Limits& limits) { return limits.max_decoded_count; },
     +[](Limits& limits, std::uint32_t value) { limits.max_decoded_count = value; }},
};

}  // namespace

#define CRF_LIMITS_CHECK_CODE(status_expression, expected_code) \
  check_status_code((status_expression), (expected_code), __FILE__, __LINE__, #status_expression)
#define CRF_LIMITS_RESULT_CODE(result_expression, expected_code) \
  check_result_code((result_expression), (expected_code), __FILE__, __LINE__, #result_expression)

// ---------------------------------------------------------------------------
// Constraint definitions
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_constraint_sets) {
  Limits limits;
  limits.max_constraint_sets = 1;

  // Persistence refuses a population larger than the bound.
  PersistentState state;
  state.epoch = CoordinatorEpoch::from_value(1);
  state.sets.push_back(finalized_set(1, 1));
  state.sets.push_back(finalized_set(2, 2));
  CRF_LIMITS_CHECK_CODE(::crf::validate_persistent_state(state, limits), ErrorCode::ResourceLimit);

  // The coordinator refuses to hold a second definition.
  ManualClock clock(1);
  const PublisherId publisher = PublisherId::from_value(41);
  const AuthorityScopeMask scopes = ::crf::scope_bit(AuthorityScope::PublishConstraintSet);
  const std::unique_ptr<Coordinator> coordinator =
      open_coordinator(limits, clock, {PublisherGrant{publisher, scopes}});
  CRF_CHECK(coordinator != nullptr);
  if (coordinator == nullptr) {
    return;
  }
  AuthorityContext context =
      authority_context(*coordinator, publisher, WorkerBootId::from_value(51),
                        ::crf::SessionId::from_value(61), MutationAttemptId::from_value(1));
  CRF_CHECK_RESULT(
      coordinator->register_publisher(context, publisher, context.worker_boot, scopes, context.session));

  context.attempt = MutationAttemptId::from_value(2);
  const auto first =
      coordinator->publish_constraint_set(context, make_set(1, {node_constraint(1, {3})}));
  CRF_CHECK_RESULT(first);
  if (!first.ok()) {
    return;
  }
  CRF_CHECK(first.value().id == ConstraintSetId::from_value(1));
  CRF_CHECK_EQ(coordinator->constraint_set_ids().size(), std::size_t{1});

  context.attempt = MutationAttemptId::from_value(3);
  const auto second =
      coordinator->publish_constraint_set(context, make_set(2, {node_constraint(1, {3})}));
  CRF_LIMITS_RESULT_CODE(second, ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(coordinator->constraint_set_ids().size(), std::size_t{1});
}

CRF_TEST(Limits, max_constraints_per_set) {
  Limits limits;
  limits.max_constraints_per_set = 3;
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;

  ConstraintSet at_bound = make_set(1, {node_constraint(1, {1}), node_constraint(2, {2}),
                                        node_constraint(3, {3})});
  CRF_CHECK_STATUS(
      ::crf::validate_and_finalize_constraint_set(at_bound, limits, defects, contradictions));

  ConstraintSet over = make_set(1, {node_constraint(1, {1}), node_constraint(2, {2}),
                                    node_constraint(3, {3}), node_constraint(4, {4})});
  CRF_LIMITS_CHECK_CODE(
      ::crf::validate_and_finalize_constraint_set(over, limits, defects, contradictions),
      ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(over.constraints.size(), std::size_t{4});

  // The evaluator reports the same bound as its primary admission reason,
  // before any semantic work happens.
  const ConstraintSet canonical = finalized_node_set(4);
  const CandidatePath candidate = make_candidate(1, 2);
  const EvaluationContext context = make_context(canonical, limits);
  const auto record = ::crf::evaluate_candidate(context, candidate);
  CRF_CHECK_RESULT(record);
  if (!record.ok()) {
    return;
  }
  CRF_CHECK(record.value().primary_reason == ReasonCode::TooManyConstraints);
  CRF_CHECK_EQ(record.value().reasons.size(), std::size_t{1});
  CRF_CHECK(record.value().outcome == Outcome::ResourceLimit);
  CRF_CHECK(!record.value().reasons_truncated);
}

CRF_TEST(Limits, max_entity_refs_per_constraint) {
  Limits limits;
  limits.max_entity_refs_per_constraint = 2;

  const Constraint at_bound = node_constraint(1, {1, 2});
  CRF_CHECK_STATUS(::crf::validate_constraint(at_bound, limits));
  const Constraint over = node_constraint(1, {1, 2, 3});
  CRF_LIMITS_CHECK_CODE(::crf::validate_constraint(over, limits), ErrorCode::ResourceLimit);

  ConstraintSet set = make_set(1, {over});
  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  CRF_LIMITS_CHECK_CODE(
      ::crf::validate_and_finalize_constraint_set(set, limits, defects, contradictions),
      ErrorCode::ResourceLimit);

  // The decoder refuses a wire list over the same bound.
  ::crf::ByteWriter writer;
  ::crf::encode_constraint(writer, over);
  ::crf::ByteReader reader(writer.span());
  Constraint decoded;
  CRF_CHECK(!::crf::decode_constraint(reader, limits, decoded));

  // A list exactly at the bound still decodes.
  ::crf::ByteWriter bound_writer;
  ::crf::encode_constraint(bound_writer, at_bound);
  ::crf::ByteReader bound_reader(bound_writer.span());
  CRF_CHECK(::crf::decode_constraint(bound_reader, limits, decoded));
  CRF_CHECK(decoded == at_bound);
}

// ---------------------------------------------------------------------------
// Candidates and evidence
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_candidates_per_evaluation) {
  Limits limits;
  limits.max_candidates_per_evaluation = 2;
  limits.max_batch_size = 2;
  const ConstraintSet set = finalized_set(1, 3);
  const EvaluationContext context = make_context(set, limits);

  std::vector<CandidatePath> candidates;
  for (std::uint64_t index = 1; index <= 3; ++index) {
    candidates.push_back(make_candidate(index, 2));
  }
  const auto result = ::crf::evaluate_batch(context, candidates);
  CRF_CHECK_RESULT(result);
  if (!result.ok()) {
    return;
  }
  CRF_CHECK(result.value().batch_outcome == BatchOutcome::BatchRejected);
  CRF_CHECK(result.value().primary_batch_reason == ReasonCode::TooManyCandidates);
  CRF_CHECK(!result.value().has_admissible);
  CRF_CHECK(result.value().records.empty());
}

CRF_TEST(Limits, max_batch_size) {
  Limits limits;
  limits.max_candidates_per_evaluation = 8;
  limits.max_batch_size = 2;
  const ConstraintSet set = finalized_set(1, 3);
  const EvaluationContext context = make_context(set, limits);

  std::vector<CandidatePath> candidates;
  for (std::uint64_t index = 1; index <= 2; ++index) {
    candidates.push_back(make_candidate(index, 2));
  }
  const auto at_bound = ::crf::evaluate_batch(context, candidates);
  CRF_CHECK_RESULT(at_bound);
  if (!at_bound.ok()) {
    return;
  }
  CRF_CHECK(at_bound.value().batch_outcome != BatchOutcome::BatchRejected);

  candidates.push_back(make_candidate(3, 2));
  const auto over = ::crf::evaluate_batch(context, candidates);
  CRF_CHECK_RESULT(over);
  if (!over.ok()) {
    return;
  }
  CRF_CHECK(over.value().batch_outcome == BatchOutcome::BatchRejected);
  CRF_CHECK(over.value().primary_batch_reason == ReasonCode::BatchTooLarge);
  CRF_CHECK(over.value().records.empty());
}

CRF_TEST(Limits, max_nodes_per_candidate) {
  Limits limits;
  limits.max_nodes_per_candidate = 3;

  const CandidatePath at_bound = make_candidate(1, 3);
  CRF_CHECK_STATUS(::crf::validate_candidate(at_bound, limits));

  const CandidatePath over = make_candidate(2, 4);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(over, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_over = over;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_over, limits),
                        ErrorCode::ResourceLimit);
}

CRF_TEST(Limits, max_links_per_candidate) {
  Limits limits;
  limits.max_nodes_per_candidate = 8;
  limits.max_links_per_candidate = 2;

  const CandidatePath at_bound = make_candidate(1, 3);
  CRF_CHECK_STATUS(::crf::validate_candidate(at_bound, limits));

  const CandidatePath over = make_candidate(2, 4);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(over, limits), ErrorCode::ResourceLimit);
  // The canonicalizer folds the link bound into its structural check, so the
  // rejection is reported as malformed input rather than as a resource limit.
  CandidatePath mutable_over = over;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_over, limits), ErrorCode::Malformed);
}

CRF_TEST(Limits, max_capabilities_per_entity) {
  Limits limits;
  limits.max_capabilities_per_entity = 2;

  CandidatePath candidate = make_candidate(1, 2);
  candidate.nodes[0].capabilities = capability_refs(2);
  CRF_CHECK_STATUS(::crf::validate_candidate(candidate, limits));
  candidate.nodes[0].capabilities = capability_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(candidate, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_node = candidate;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_node, limits),
                        ErrorCode::ResourceLimit);

  CandidatePath link_case = make_candidate(2, 2);
  link_case.links[0].capabilities = capability_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(link_case, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_link = link_case;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_link, limits),
                        ErrorCode::ResourceLimit);
}

CRF_TEST(Limits, max_domains_per_entity) {
  Limits limits;
  limits.max_domains_per_entity = 2;

  CandidatePath candidate = make_candidate(1, 2);
  candidate.nodes[0].domains = domain_refs(2);
  CRF_CHECK_STATUS(::crf::validate_candidate(candidate, limits));
  candidate.nodes[0].domains = domain_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(candidate, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_node = candidate;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_node, limits),
                        ErrorCode::ResourceLimit);

  CandidatePath link_case = make_candidate(2, 2);
  link_case.links[0].domains = domain_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(link_case, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_link = link_case;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_link, limits),
                        ErrorCode::ResourceLimit);
}

CRF_TEST(Limits, max_localities_per_entity) {
  Limits limits;
  limits.max_localities_per_entity = 2;

  CandidatePath candidate = make_candidate(1, 2);
  candidate.nodes[0].localities = locality_refs(2);
  CRF_CHECK_STATUS(::crf::validate_candidate(candidate, limits));
  candidate.nodes[0].localities = locality_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(candidate, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_node = candidate;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_node, limits),
                        ErrorCode::ResourceLimit);
}

CRF_TEST(Limits, max_policies_per_candidate) {
  Limits limits;
  limits.max_policies_per_candidate = 2;

  CandidatePath candidate = make_candidate(1, 2);
  candidate.policies = policy_refs(2);
  CRF_CHECK_STATUS(::crf::validate_candidate(candidate, limits));
  candidate.policies = policy_refs(3);
  CRF_LIMITS_CHECK_CODE(::crf::validate_candidate(candidate, limits), ErrorCode::ResourceLimit);
  CandidatePath mutable_candidate = candidate;
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_candidate(mutable_candidate, limits),
                        ErrorCode::ResourceLimit);
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_explanation_reasons) {
  // Three mandatory constraints requiring four absent nodes each: twelve
  // reasons in total, and no per-constraint truncation at this bound.
  Limits reference_limits;
  reference_limits.max_explanation_reasons = 64;
  const ConstraintSet set = finalized_failing_set(reference_limits, 3, 4);
  const CandidatePath candidate = make_candidate(500, 2);
  const auto reference = ::crf::evaluate_candidate(make_context(set, reference_limits), candidate);
  CRF_CHECK_RESULT(reference);
  if (!reference.ok()) {
    return;
  }
  CRF_CHECK_EQ(reference.value().reasons.size(), std::size_t{12});
  CRF_CHECK(!reference.value().reasons_truncated);
  CRF_CHECK(reference.value().primary_reason == ReasonCode::RequiredNodeAbsent);
  CRF_CHECK(reference.value().outcome == Outcome::HardConstraintFailed);
  const Reason reference_primary = reference.value().reasons.front();

  // The same input under a bound of eight reasons.
  Limits tight_limits = reference_limits;
  tight_limits.max_explanation_reasons = 8;
  const auto tight = ::crf::evaluate_candidate(make_context(set, tight_limits), candidate);
  CRF_CHECK_RESULT(tight);
  if (!tight.ok()) {
    return;
  }
  CRF_CHECK_EQ(tight.value().reasons.size(), std::size_t{8});
  CRF_CHECK(tight.value().reasons_truncated);
  CRF_CHECK(tight.value().primary_reason == ReasonCode::RequiredNodeAbsent);
  CRF_CHECK(tight.value().outcome == Outcome::HardConstraintFailed);
  // The primary reason is the deterministic minimum and is always retained, so
  // truncation never changes the outcome.
  CRF_CHECK(same_reason(tight.value().reasons.front(), reference_primary));
  CRF_CHECK(tight.value().primary_reason == reference.value().primary_reason);
  for (std::size_t index = 0; index < tight.value().reasons.size(); ++index) {
    CRF_CHECK(same_reason(tight.value().reasons[index], reference.value().reasons[index]));
  }

  // The validation floor of four reasons truncates harder and still keeps the
  // same primary reason.
  Limits floor_limits = reference_limits;
  floor_limits.max_explanation_reasons = 4;
  const auto floor = ::crf::evaluate_candidate(make_context(set, floor_limits), candidate);
  CRF_CHECK_RESULT(floor);
  if (!floor.ok()) {
    return;
  }
  CRF_CHECK_EQ(floor.value().reasons.size(), std::size_t{4});
  CRF_CHECK(floor.value().reasons_truncated);
  CRF_CHECK(same_reason(floor.value().reasons.front(), reference_primary));
}

CRF_TEST(Limits, max_failed_constraints_per_evaluation_bounds_distinct_constraints) {
  // This bound caps how many distinct constraints may be represented in one
  // reason vector. The primary reason is always the first element, so lowering
  // the bound never changes the outcome.
  Limits default_limits;
  const ConstraintSet set = finalized_failing_set(default_limits, 3, 4);
  const CandidatePath candidate = make_candidate(501, 2);

  Limits one_failed;
  one_failed.max_failed_constraints_per_evaluation = 1;
  Limits two_failed;
  two_failed.max_failed_constraints_per_evaluation = 2;
  CRF_CHECK(one_failed.max_failed_constraints_per_evaluation !=
            default_limits.max_failed_constraints_per_evaluation);

  const auto one = ::crf::evaluate_candidate(make_context(set, one_failed), candidate);
  const auto two = ::crf::evaluate_candidate(make_context(set, two_failed), candidate);
  const auto standard = ::crf::evaluate_candidate(make_context(set, default_limits), candidate);
  CRF_CHECK_RESULT(one);
  CRF_CHECK_RESULT(two);
  CRF_CHECK_RESULT(standard);
  if (!one.ok() || !two.ok() || !standard.ok()) {
    return;
  }
  const auto distinct_constraints = [](const ::crf::EvaluationRecord& record) {
    std::vector<std::uint32_t> ordinals;
    for (const ::crf::Reason& reason : record.reasons) {
      bool seen = false;
      for (const std::uint32_t ordinal : ordinals) {
        if (ordinal == reason.constraint_ordinal) {
          seen = true;
        }
      }
      if (!seen) {
        ordinals.push_back(reason.constraint_ordinal);
      }
    }
    return ordinals.size();
  };
  CRF_CHECK_EQ(distinct_constraints(one.value()), std::size_t{1});
  CRF_CHECK_EQ(distinct_constraints(two.value()), std::size_t{2});
  CRF_CHECK_EQ(distinct_constraints(standard.value()), std::size_t{3});
  CRF_CHECK_EQ(one.value().reasons.size(), std::size_t{4});
  CRF_CHECK_EQ(two.value().reasons.size(), std::size_t{8});
  CRF_CHECK_EQ(standard.value().reasons.size(), std::size_t{12});
  CRF_CHECK(one.value().reasons_truncated);
  CRF_CHECK(!standard.value().reasons_truncated);
  CRF_CHECK(one.value().primary_reason == standard.value().primary_reason);
  for (std::size_t index = 0; index < one.value().reasons.size(); ++index) {
    CRF_CHECK(same_reason(one.value().reasons[index], standard.value().reasons[index]));
  }

  // The per-constraint reason cap is a fixed eight: one constraint requiring
  // sixteen absent nodes yields exactly eight reasons and marks truncation.
  Limits reference_limits;
  reference_limits.max_explanation_reasons = 64;
  const ConstraintSet single = finalized_failing_set(reference_limits, 1, 16);
  const auto single_record =
      ::crf::evaluate_candidate(make_context(single, reference_limits), candidate);
  CRF_CHECK_RESULT(single_record);
  if (!single_record.ok()) {
    return;
  }
  CRF_CHECK_EQ(single_record.value().reasons.size(), std::size_t{8});
  CRF_CHECK(single_record.value().reasons_truncated);
  for (const Reason& reason : single_record.value().reasons) {
    CRF_CHECK_EQ(reason.constraint_ordinal, std::uint32_t{0});
  }
}

CRF_TEST(Limits, SnapshotsArePureFunctionsOfADefinition) {
  // Snapshots are computed on demand and retained nowhere, so no retention
  // bound exists: creating many of them is unbounded by configuration.
  Limits limits;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));
  std::vector<::crf::SnapshotId> ids;
  for (std::uint64_t index = 1; index <= 3; ++index) {
    const ConstraintSet set = finalized_set(index, index);
    const ::crf::DefinitionsSnapshot snapshot = ::crf::snapshot_definitions(set);
    ids.push_back(snapshot.id);
  }
  CRF_CHECK_EQ(ids.size(), std::size_t{3});
  CRF_CHECK(ids[0] != ids[1]);
  CRF_CHECK(ids[1] != ids[2]);
  CRF_CHECK(ids[0] != ids[2]);
}

CRF_TEST(Limits, PersistedEntityCountsAreBoundedByTheGovernedLimit) {
  // A durable record's entity counts are bounded by the limit that governs the
  // collection itself; there is no separate aggregate ceiling to leave dead.
  Limits limits;
  limits.max_entity_refs_per_constraint = 4;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));
  PersistentState state;
  state.epoch = CoordinatorEpoch::from_value(1);
  state.sets.push_back(finalized_failing_set(Limits{}, 1, 16));
  CRF_CHECK_EQ(state.sets[0].constraints[0].nodes.size(), std::size_t{16});
  CRF_LIMITS_CHECK_CODE(::crf::validate_persistent_state(state, limits),
                        ::crf::ErrorCode::ResourceLimit);
}

// ---------------------------------------------------------------------------
// Authority and distributed admission
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_publishers) {
  Limits limits;
  limits.max_publishers = 1;
  ManualClock clock(1);
  const PublisherId first_publisher = PublisherId::from_value(11);
  const PublisherId second_publisher = PublisherId::from_value(12);
  const AuthorityScopeMask scopes = ::crf::scope_bit(AuthorityScope::PublishConstraintSet);
  const std::unique_ptr<Coordinator> coordinator =
      open_coordinator(limits, clock, {PublisherGrant{first_publisher, scopes},
                                       PublisherGrant{second_publisher, scopes}});
  CRF_CHECK(coordinator != nullptr);
  if (coordinator == nullptr) {
    return;
  }
  AuthorityContext context =
      authority_context(*coordinator, first_publisher, WorkerBootId::from_value(21),
                        ::crf::SessionId::from_value(31), MutationAttemptId::from_value(1));
  CRF_CHECK_RESULT(coordinator->register_publisher(context, first_publisher, context.worker_boot,
                                                   scopes, context.session));
  CRF_CHECK_EQ(coordinator->authority().live_publishers(), std::size_t{1});

  // A second publisher in the same session is refused by the publisher bound,
  // not by the session bound.
  const auto second = coordinator->register_publisher(context, second_publisher,
                                                      WorkerBootId::from_value(22), scopes,
                                                      context.session);
  CRF_LIMITS_RESULT_CODE(second, ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(coordinator->authority().live_publishers(), std::size_t{1});
}

CRF_TEST(Limits, max_sessions) {
  Limits limits;
  limits.max_publishers = 4;
  limits.max_sessions = 1;
  ManualClock clock(1);
  const PublisherId first_publisher = PublisherId::from_value(11);
  const PublisherId second_publisher = PublisherId::from_value(12);
  const AuthorityScopeMask scopes = ::crf::scope_bit(AuthorityScope::PublishConstraintSet);
  const std::unique_ptr<Coordinator> coordinator =
      open_coordinator(limits, clock, {PublisherGrant{first_publisher, scopes},
                                       PublisherGrant{second_publisher, scopes}});
  CRF_CHECK(coordinator != nullptr);
  if (coordinator == nullptr) {
    return;
  }
  AuthorityContext context =
      authority_context(*coordinator, first_publisher, WorkerBootId::from_value(21),
                        ::crf::SessionId::from_value(31), MutationAttemptId::from_value(1));
  CRF_CHECK_RESULT(coordinator->register_publisher(context, first_publisher, context.worker_boot,
                                                   scopes, context.session));
  CRF_CHECK_EQ(coordinator->authority().live_sessions(), std::size_t{1});

  // A second, distinct session exceeds the session bound while the publisher
  // bound still has spare capacity.
  const auto second =
      coordinator->register_publisher(context, second_publisher, WorkerBootId::from_value(22),
                                      scopes, ::crf::SessionId::from_value(32));
  CRF_LIMITS_RESULT_CODE(second, ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(coordinator->authority().live_sessions(), std::size_t{1});
  CRF_CHECK_EQ(coordinator->authority().live_publishers(), std::size_t{1});
}

CRF_TEST(Limits, max_fenced_boots) {
  Limits limits;
  limits.max_fenced_boots = 2;
  AuthorityRegistry registry;
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(1)));

  CRF_CHECK_STATUS(registry.fence_boot(WorkerBootId::from_value(1), CoordinatorEpoch::from_value(1),
                                       5, limits));
  CRF_CHECK_STATUS(registry.fence_boot(WorkerBootId::from_value(2), CoordinatorEpoch::from_value(1),
                                       6, limits));
  CRF_CHECK_EQ(registry.fenced_boots(), std::size_t{2});

  CRF_LIMITS_CHECK_CODE(registry.fence_boot(WorkerBootId::from_value(3),
                                            CoordinatorEpoch::from_value(1), 7, limits),
                        ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(registry.fenced_boots(), std::size_t{2});
  CRF_CHECK(!registry.is_boot_fenced(WorkerBootId::from_value(3)));

  // Re-fencing a boot that is already fenced is idempotent and never consumes
  // capacity, so the bound cannot be reached by a repeated request.
  CRF_CHECK_STATUS(registry.fence_boot(WorkerBootId::from_value(1), CoordinatorEpoch::from_value(1),
                                       8, limits));
  CRF_CHECK_EQ(registry.fenced_boots(), std::size_t{2});
}

CRF_TEST(Limits, max_mutation_attempts) {
  Limits limits;
  limits.max_mutation_attempts = 2;
  AuthorityRegistry registry;

  CRF_CHECK_RESULT(registry.observe_attempt(MutationAttemptId::from_value(1), attempt_digest(1), 1,
                                            limits));
  CRF_CHECK_RESULT(registry.observe_attempt(MutationAttemptId::from_value(2), attempt_digest(2), 2,
                                            limits));
  CRF_CHECK_RESULT(registry.observe_attempt(MutationAttemptId::from_value(3), attempt_digest(3), 3,
                                            limits));
  CRF_CHECK_EQ(registry.attempts().size(), std::size_t{2});

  // The oldest attempt was evicted, so its identity is fresh again.
  const auto evicted =
      registry.observe_attempt(MutationAttemptId::from_value(1), attempt_digest(1), 4, limits);
  CRF_CHECK_RESULT(evicted);
  if (!evicted.ok()) {
    return;
  }
  CRF_CHECK(evicted.value() == ReplayVerdict::Fresh);
  CRF_CHECK_EQ(registry.attempts().size(), std::size_t{2});

  // The attempts still inside the window are de-duplicated exactly.
  const auto exact =
      registry.observe_attempt(MutationAttemptId::from_value(3), attempt_digest(3), 5, limits);
  CRF_CHECK_RESULT(exact);
  if (!exact.ok()) {
    return;
  }
  CRF_CHECK(exact.value() == ReplayVerdict::ExactReplay);
  const auto conflict =
      registry.observe_attempt(MutationAttemptId::from_value(3), attempt_digest(99), 6, limits);
  CRF_CHECK_RESULT(conflict);
  if (!conflict.ok()) {
    return;
  }
  CRF_CHECK(conflict.value() == ReplayVerdict::Conflict);
  CRF_CHECK_EQ(registry.attempts().size(), std::size_t{2});
}

// ---------------------------------------------------------------------------
// Wire frames
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_frame_bytes) {
  Limits limits;
  limits.max_frame_bytes = 64;
  limits.max_frame_assembly_bytes = 4096;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  ::crf::Frame at_bound;
  at_bound.header.message = ::crf::MessageId::Hello;
  at_bound.payload.assign(64, std::byte{0x11});
  std::vector<std::byte> encoded;
  CRF_CHECK_STATUS(::crf::encode_frame(at_bound, limits, encoded));
  CRF_CHECK_EQ(encoded.size(), ::crf::frame_size(64));
  // A payload exactly at the bound passes the frame's admission check, so the
  // decoder does not report the bound for it. (A frame with a non-empty payload
  // is not otherwise decodable today; that defect is reported separately.)
  ::crf::Frame decoded;
  CRF_CHECK(::crf::decode_frame(encoded, limits, decoded).code() != ErrorCode::ResourceLimit);

  ::crf::Frame over = at_bound;
  over.payload.assign(65, std::byte{0x11});
  CRF_LIMITS_CHECK_CODE(::crf::encode_frame(over, limits, encoded), ErrorCode::ResourceLimit);

  // A frame encoded elsewhere that declares an oversized payload is refused on
  // decode, and the assembler refuses a started frame that declares one.
  std::vector<std::byte> oversized;
  CRF_CHECK_STATUS(::crf::encode_frame(over, Limits{}, oversized));
  CRF_LIMITS_CHECK_CODE(::crf::decode_frame(oversized, limits, decoded), ErrorCode::ResourceLimit);

  ::crf::FrameAssembler assembler(limits);
  const std::size_t header_bytes = ::crf::frame_size(0);
  CRF_CHECK(header_bytes > 0);
  CRF_CHECK_STATUS(
      assembler.push(std::span<const std::byte>(oversized.data(), header_bytes)));
  bool produced = false;
  CRF_LIMITS_CHECK_CODE(assembler.pop(decoded, produced), ErrorCode::ResourceLimit);
  CRF_CHECK(!produced);
  CRF_CHECK(assembler.failed());
}

CRF_TEST(Limits, max_frame_assembly_bytes) {
  Limits limits;
  limits.max_frame_bytes = 64;
  limits.max_frame_assembly_bytes = 128;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  ::crf::FrameAssembler assembler(limits);
  const std::vector<std::byte> chunk(128, std::byte{0x22});
  CRF_CHECK_STATUS(assembler.push(chunk));
  CRF_CHECK_EQ(assembler.buffered_bytes(), std::size_t{128});
  CRF_LIMITS_CHECK_CODE(assembler.push(std::span<const std::byte>(chunk.data(), 1)),
                        ErrorCode::ResourceLimit);
  CRF_CHECK(assembler.failed());
  CRF_CHECK_EQ(assembler.buffered_bytes(), std::size_t{0});
  CRF_LIMITS_CHECK_CODE(assembler.push(chunk), ErrorCode::ProtocolViolation);
  assembler.reset();
  CRF_CHECK(!assembler.failed());

  // A real frame reassembles across fragments while it stays inside the bound.
  // The payload is empty because a non-empty frame does not currently
  // round-trip through ::crf::decode_frame; that defect is reported separately.
  ::crf::Frame frame;
  frame.header.message = ::crf::MessageId::Heartbeat;
  std::vector<std::byte> encoded;
  CRF_CHECK_STATUS(::crf::encode_frame(frame, limits, encoded));
  CRF_CHECK(encoded.size() <= limits.max_frame_assembly_bytes);
  const std::size_t split = encoded.size() / 2;
  CRF_CHECK_STATUS(assembler.push(std::span<const std::byte>(encoded.data(), split)));
  ::crf::Frame popped;
  bool produced = false;
  CRF_CHECK_STATUS(assembler.pop(popped, produced));
  CRF_CHECK(!produced);
  CRF_CHECK_STATUS(assembler.push(
      std::span<const std::byte>(encoded.data() + split, encoded.size() - split)));
  CRF_CHECK_STATUS(assembler.pop(popped, produced));
  CRF_CHECK(produced);
  CRF_CHECK(popped.header.message == ::crf::MessageId::Heartbeat);
  CRF_CHECK(popped.payload.empty());
  CRF_CHECK_EQ(assembler.buffered_bytes(), std::size_t{0});
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_persistence_record_bytes) {
  Limits limits;
  limits.max_persistence_record_bytes = 1024;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  // A durable envelope that declares a payload over the bound is refused.
  const std::vector<std::byte> big_payload(4096, std::byte{0x5a});
  const std::vector<std::byte> envelope = ::crf::encode_envelope(big_payload);
  std::vector<std::byte> decoded_payload;
  CRF_LIMITS_CHECK_CODE(::crf::decode_envelope(envelope, limits, decoded_payload),
                        ErrorCode::ResourceLimit);
  CRF_CHECK_STATUS(::crf::decode_envelope(envelope, Limits{}, decoded_payload));
  CRF_CHECK(decoded_payload == big_payload);

  // A state whose encoding exceeds the record bound is refused by save before
  // anything reaches the disk.
  PersistentState state;
  state.epoch = CoordinatorEpoch::from_value(1);
  state.initialized = true;
  for (std::uint64_t index = 1; index <= 12; ++index) {
    state.sets.push_back(finalized_set(100 + index, index));
  }
  ::crf::ByteWriter writer;
  ::crf::encode_persistent_state(writer, state);
  CRF_CHECK(writer.size() > limits.max_persistence_record_bytes);

  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "crf_test_limits_store.bin";
  std::error_code error;
  std::filesystem::remove(path, error);
  auto store = ::crf::DurableStore::open(path.string(), limits, true);
  CRF_CHECK_RESULT(store);
  if (!store.ok()) {
    return;
  }
  CRF_LIMITS_CHECK_CODE(store.value()->save(state), ErrorCode::ResourceLimit);
  CRF_CHECK_EQ(store.value()->successful_writes(), std::uint64_t{0});
  CRF_CHECK_EQ(store.value()->failed_writes(), std::uint64_t{1});
  CRF_CHECK(!store.value()->exists());
  std::filesystem::remove(path, error);
}

CRF_TEST(Limits, max_evaluations_retained) {
  // Direct bite: the invalidation index refuses more tracked evaluations than
  // may be retained.
  Limits index_limits;
  index_limits.max_evaluations_retained = 1;
  InvalidationIndex index;
  CRF_CHECK_STATUS(index.bind(InvalidationKey{InvalidationKeyKind::Node, 1},
                              ::crf::ConstraintEvaluationId::from_value(1)));
  CRF_CHECK_STATUS(index.check_limits(index_limits));
  CRF_CHECK_STATUS(index.bind(InvalidationKey{InvalidationKeyKind::Node, 2},
                              ::crf::ConstraintEvaluationId::from_value(2)));
  CRF_LIMITS_CHECK_CODE(index.check_limits(index_limits), ErrorCode::ResourceLimit);

  // The coordinator trims its history to the same bound: each new evaluation
  // supersedes the previous one and the superseded record is evicted.
  Limits limits;
  limits.max_evaluations_retained = 1;
  ManualClock clock(1);
  const PublisherId publisher = PublisherId::from_value(41);
  const AuthorityScopeMask scopes = ::crf::scope_bit(AuthorityScope::PublishConstraintSet) |
                                    ::crf::scope_bit(AuthorityScope::PublishEvaluation);
  const std::unique_ptr<Coordinator> coordinator =
      open_coordinator(limits, clock, {PublisherGrant{publisher, scopes}});
  CRF_CHECK(coordinator != nullptr);
  if (coordinator == nullptr) {
    return;
  }
  AuthorityContext context =
      authority_context(*coordinator, publisher, WorkerBootId::from_value(71),
                        ::crf::SessionId::from_value(81), MutationAttemptId::from_value(1));
  CRF_CHECK_RESULT(
      coordinator->register_publisher(context, publisher, context.worker_boot, scopes, context.session));

  context.attempt = MutationAttemptId::from_value(2);
  const auto published =
      coordinator->publish_constraint_set(context, make_set(1, {node_constraint(1, {3})}));
  CRF_CHECK_RESULT(published);
  if (!published.ok()) {
    return;
  }
  const ConstraintSetId set_id = published.value().id;
  const CandidatePath candidate = make_candidate(700, 2);
  const std::span<const CandidatePath> candidates(&candidate, 1);
  for (std::uint64_t attempt = 3; attempt <= 5; ++attempt) {
    context.attempt = MutationAttemptId::from_value(attempt);
    const auto outcome = coordinator->evaluate(context, set_id, candidates);
    CRF_CHECK_RESULT(outcome);
    if (!outcome.ok()) {
      return;
    }
    CRF_CHECK(outcome.value().committed);
    CRF_CHECK(coordinator->stored_evaluation_count() <=
              static_cast<std::size_t>(limits.max_evaluations_retained));
  }
  CRF_CHECK_EQ(coordinator->stored_evaluation_count(), std::size_t{1});
}

// ---------------------------------------------------------------------------
// Naming and detail text
// ---------------------------------------------------------------------------

CRF_TEST(Limits, max_name_bytes) {
  Limits limits;
  limits.max_name_bytes = 4;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  ConstraintSet set = make_set(9, {node_constraint(1, {3})});
  set.name = "abcd";
  std::vector<SetDefect> defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(set, limits, defects));
  set.name = "abcde";
  CRF_LIMITS_CHECK_CODE(::crf::canonicalize_constraint_set(set, limits, defects),
                        ErrorCode::ResourceLimit);

  // The decoder refuses a persisted name over the bound.
  ConstraintSet long_name = make_set(10, {node_constraint(1, {3})});
  long_name.name = std::string(120, 'n');
  std::vector<SetDefect> long_defects;
  CRF_CHECK_STATUS(::crf::canonicalize_constraint_set(long_name, Limits{}, long_defects));
  ::crf::ByteWriter writer;
  ::crf::encode_constraint_set(writer, long_name);
  ::crf::ByteReader reader(writer.span());
  ConstraintSet decoded;
  CRF_CHECK(!::crf::decode_constraint_set(reader, limits, decoded));

  // The hello codec applies the same bound to the client name.
  ::crf::HelloPayload hello;
  hello.publisher = PublisherId::from_value(1);
  hello.worker_boot = WorkerBootId::from_value(1);
  hello.requested_scopes = ::crf::scope_bit(AuthorityScope::PublishConstraintSet);
  hello.client_name = "abcd";
  ::crf::ByteWriter hello_writer;
  ::crf::encode_hello(hello_writer, hello);
  ::crf::ByteReader hello_reader(hello_writer.span());
  ::crf::HelloPayload decoded_hello;
  CRF_CHECK(::crf::decode_hello(hello_reader, limits, decoded_hello));
  CRF_CHECK_EQ(decoded_hello.client_name, std::string("abcd"));
  ::crf::HelloPayload long_hello = hello;
  long_hello.client_name = "abcde";
  ::crf::ByteWriter long_writer;
  ::crf::encode_hello(long_writer, long_hello);
  ::crf::ByteReader long_reader(long_writer.span());
  CRF_CHECK(!::crf::decode_hello(long_reader, limits, decoded_hello));
}

CRF_TEST(Limits, max_detail_bytes) {
  Limits limits;
  limits.max_detail_bytes = 8;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  ::crf::ErrorReportPayload payload;
  payload.code = ErrorCode::Malformed;
  payload.reason = ReasonCode::MalformedFrame;
  payload.detail = "detail text longer than eight bytes";
  ::crf::ByteWriter writer;
  ::crf::encode_error_report(writer, payload);
  ::crf::ByteReader reader(writer.span());
  ::crf::ErrorReportPayload decoded;
  CRF_CHECK(!::crf::decode_error_report(reader, limits, decoded));

  ::crf::ErrorReportPayload exact;
  exact.detail = "12345678";
  ::crf::ByteWriter exact_writer;
  ::crf::encode_error_report(exact_writer, exact);
  ::crf::ByteReader exact_reader(exact_writer.span());
  CRF_CHECK(::crf::decode_error_report(exact_reader, limits, decoded));
  CRF_CHECK_EQ(decoded.detail, std::string("12345678"));
}

CRF_TEST(Limits, max_decoded_count) {
  Limits limits;
  limits.max_decoded_count = 2;
  limits.max_evaluations_retained = 8;
  std::string why;
  CRF_CHECK(::crf::validate_limits(limits, why));

  InvalidationIndex index;
  CRF_CHECK_STATUS(index.bind(InvalidationKey{InvalidationKeyKind::Node, 1},
                              ::crf::ConstraintEvaluationId::from_value(1)));
  CRF_CHECK_STATUS(index.bind(InvalidationKey{InvalidationKeyKind::Path, 2},
                              ::crf::ConstraintEvaluationId::from_value(1)));
  CRF_CHECK_EQ(index.key_count(), std::size_t{2});
  CRF_CHECK_STATUS(index.check_limits(limits));
  CRF_CHECK_STATUS(index.bind(InvalidationKey{InvalidationKeyKind::Node, 3},
                              ::crf::ConstraintEvaluationId::from_value(1)));
  CRF_CHECK_EQ(index.key_count(), std::size_t{3});
  CRF_LIMITS_CHECK_CODE(index.check_limits(limits), ErrorCode::ResourceLimit);
  CRF_CHECK_STATUS(index.validate());
}

// ---------------------------------------------------------------------------
// The limit set itself
// ---------------------------------------------------------------------------

CRF_TEST(Limits, validate_limits_rejects_zero_and_above_absolute) {
  std::string why;
  CRF_CHECK(::crf::validate_limits(Limits{}, why));
  CRF_CHECK(why.empty());

  // Every declared field rejects both a zero value and a value above the
  // absolute ceiling, naming itself in the explanation.
  std::size_t checked = 0;
  for (const LimitField& field : kLimitFields) {
    Limits zeroed;
    field.set(zeroed, 0);
    why.clear();
    CRF_CHECK(!::crf::validate_limits(zeroed, why));
    CRF_CHECK(why.find(field.name) != std::string::npos);

    Limits above;
    field.set(above, ::crf::kAbsoluteMaxLimit + 1);
    why.clear();
    CRF_CHECK(!::crf::validate_limits(above, why));
    CRF_CHECK(why.find(field.name) != std::string::npos);
    ++checked;
  }
  CRF_CHECK_EQ(checked, std::size_t{24});

  // Cross-field rules.
  {
    Limits limits;
    limits.max_frame_bytes = 1024;
    limits.max_frame_assembly_bytes = 512;
    why.clear();
    CRF_CHECK(!::crf::validate_limits(limits, why));
    CRF_CHECK(why.find("max_frame_assembly_bytes") != std::string::npos);
  }
  {
    Limits limits;
    limits.max_nodes_per_candidate = 1;
    why.clear();
    CRF_CHECK(!::crf::validate_limits(limits, why));
    CRF_CHECK(why.find("max_nodes_per_candidate") != std::string::npos);
  }
  {
    Limits limits;
    limits.max_explanation_reasons = 3;
    why.clear();
    CRF_CHECK(!::crf::validate_limits(limits, why));
    CRF_CHECK(why.find("max_explanation_reasons") != std::string::npos);
  }
  {
    Limits limits;
    limits.max_persistence_record_bytes = 1023;
    why.clear();
    CRF_CHECK(!::crf::validate_limits(limits, why));
    CRF_CHECK(why.find("max_persistence_record_bytes") != std::string::npos);
  }
}

CRF_TEST(Limits, every_configured_limit_is_referenced) {
  std::size_t referenced = 0;
  std::size_t unconsulted = 0;
  for (const LimitField& field : kLimitFields) {
    CRF_CHECK(field.name != nullptr && field.name[0] != '\0');
    CRF_CHECK(field.exercised_by != nullptr && field.exercised_by[0] != '\0');
    const Limits defaults;
    CRF_CHECK_EQ(field.get(defaults), field.documented_default);
    if (!field.consulted_by_library) {
      ++unconsulted;
    }
    ++referenced;
  }
  CRF_CHECK_EQ(referenced, std::size_t{24});
  // Every declared bound now has a real enforcement site; a bound that nothing
  // consults would be a defect and would fail here.
  CRF_CHECK_EQ(unconsulted, std::size_t{0});
}
