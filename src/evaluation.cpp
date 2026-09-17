// Constraint Routing Fabric -- outcomes, reasons and evaluation records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/evaluation.hpp"

#include <string>

namespace crf {
namespace {

/// Reads a generation field. Zero means "not bound" and is representable.
template <class Tag>
[[nodiscard]] bool read_generation(ByteReader& reader, std::uint64_t raw, Generation<Tag>& out) {
  if (raw == 0) {
    out = Generation<Tag>{};
    return true;
  }
  if (!Generation<Tag>::is_representable(raw)) {
    reader.fail();
    return false;
  }
  out = Generation<Tag>::from_value(raw);
  return true;
}

void write_evidence(ByteWriter& writer, const EvidenceGenerationSet& evidence) {
  writer.put_u64(evidence.topology.value());
  writer.put_u64(evidence.link_state.value());
  writer.put_u64(evidence.capability.value());
  writer.put_u64(evidence.failure_domain.value());
  writer.put_u64(evidence.policy.value());
  writer.put_u64(evidence.planner.value());
  writer.put_u64(evidence.path_authority.value());
  writer.put_u32(evidence.consulted);
  writer.put_u64(evidence.captured_tick);
}

[[nodiscard]] bool read_evidence(ByteReader& reader, EvidenceGenerationSet& out) {
  std::uint64_t topology = 0;
  std::uint64_t link_state = 0;
  std::uint64_t capability = 0;
  std::uint64_t failure_domain = 0;
  std::uint64_t policy = 0;
  std::uint64_t planner = 0;
  std::uint64_t path_authority = 0;
  if (!reader.u64(topology) || !reader.u64(link_state) || !reader.u64(capability) ||
      !reader.u64(failure_domain) || !reader.u64(policy) || !reader.u64(planner) ||
      !reader.u64(path_authority) || !reader.u32(out.consulted) || !reader.u64(out.captured_tick)) {
    return false;
  }
  return read_generation(reader, topology, out.topology) &&
         read_generation(reader, link_state, out.link_state) &&
         read_generation(reader, capability, out.capability) &&
         read_generation(reader, failure_domain, out.failure_domain) &&
         read_generation(reader, policy, out.policy) &&
         read_generation(reader, planner, out.planner) &&
         read_generation(reader, path_authority, out.path_authority);
}

void feed_evidence(SemanticHasher& hasher, const EvidenceGenerationSet& evidence) {
  hasher.put_u64(evidence.topology.value());
  hasher.put_u64(evidence.link_state.value());
  hasher.put_u64(evidence.capability.value());
  hasher.put_u64(evidence.failure_domain.value());
  hasher.put_u64(evidence.policy.value());
  hasher.put_u64(evidence.planner.value());
  hasher.put_u64(evidence.path_authority.value());
  hasher.put_u32(evidence.consulted);
}

[[nodiscard]] bool known_outcome(std::uint16_t raw) noexcept { return raw <= 10; }
[[nodiscard]] bool known_reason_class(std::uint8_t raw) noexcept { return raw <= 8; }
[[nodiscard]] bool known_subject_kind(std::uint8_t raw) noexcept { return raw <= 15; }
[[nodiscard]] bool known_result_state(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 5;
}
[[nodiscard]] bool known_evidence_family(std::uint8_t raw) noexcept { return raw <= 8; }
[[nodiscard]] bool known_constraint_kind(std::uint16_t raw) noexcept { return raw <= 18; }

}  // namespace

bool operator==(const Provenance& a, const Provenance& b) noexcept {
  return a.epoch == b.epoch && a.publisher == b.publisher && a.worker_boot == b.worker_boot &&
         a.attempt == b.attempt && a.request == b.request;
}

bool same_evidence_binding(const EvidenceGenerationSet& a, const EvidenceGenerationSet& b) noexcept {
  return a.topology == b.topology && a.link_state == b.link_state && a.capability == b.capability &&
         a.failure_domain == b.failure_domain && a.policy == b.policy && a.planner == b.planner &&
         a.path_authority == b.path_authority;
}

ReasonClass reason_class_of(ReasonCode code) noexcept {
  const auto value = static_cast<std::uint16_t>(code);
  if (value >= 100 && value < 200) return ReasonClass::ResourceAdmission;
  if (value >= 200 && value < 300) return ReasonClass::WireDecode;
  if (value >= 300 && value < 400) return ReasonClass::CallerIdentity;
  if (value >= 400 && value < 500) return ReasonClass::EpochBootScope;
  if (value >= 500 && value < 600) return ReasonClass::ConstraintSetLifecycle;
  if (value >= 600 && value < 700) return ReasonClass::PathAuthority;
  if (value >= 700 && value < 800) return ReasonClass::EvidenceCurrentness;
  if (value >= 800 && value < 900) return ReasonClass::MandatoryConstraint;
  return ReasonClass::Preference;
}

Outcome outcome_of(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::None:
      return Outcome::Admissible;
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
    case ReasonCode::PathNotLegal:
    case ReasonCode::ConstraintSetRevoked:
      return Outcome::Unauthorized;
    case ReasonCode::StaleCoordinatorEpoch:
    case ReasonCode::FutureCoordinatorEpoch:
    case ReasonCode::FencedWorkerBoot:
    case ReasonCode::UnknownWorkerBoot:
    case ReasonCode::WorkerBootReused:
      return Outcome::Unauthorized;
    case ReasonCode::PathAuthorityNotEvaluated:
    case ReasonCode::PathAuthorityGenerationMissing:
      return Outcome::UnknownRequiredEvidence;
    case ReasonCode::StalePathAuthority:
      return Outcome::StalePathAuthority;
    case ReasonCode::ConstraintSetNotFound:
    case ReasonCode::ConstraintSetNotActive:
    case ReasonCode::ConstraintSetSuspended:
    case ReasonCode::ConstraintSetSuperseded:
    case ReasonCode::ConstraintSetRetired:
    case ReasonCode::StaleConstraintSetGeneration:
    case ReasonCode::ContradictoryConstraintSet:
      return Outcome::StaleConstraintSet;
    case ReasonCode::ConstraintSetRevalidationRequired:
      return Outcome::RevalidationRequired;
    case ReasonCode::StaleTopologyEvidence:
    case ReasonCode::StaleLinkStateEvidence:
    case ReasonCode::StaleCapabilityEvidence:
    case ReasonCode::StaleFailureDomainEvidence:
    case ReasonCode::StalePolicyEvidence:
    case ReasonCode::StalePlannerEvidence:
    case ReasonCode::EvidenceAgeExceeded:
    case ReasonCode::EvidenceNotBound:
      return Outcome::StaleEvidence;
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
    default:
      return Outcome::HardConstraintFailed;
  }
}

int compare_reason(const Reason& a, const Reason& b) noexcept {
  if (a.reason_class != b.reason_class) return a.reason_class < b.reason_class ? -1 : 1;
  // Within a class, the canonical constraint order dominates: the documented
  // precedence is "mandatory constraints in canonical order". Reasons that are
  // not bound to a constraint carry ordinal zero and fall back to code order.
  if (a.constraint_ordinal != b.constraint_ordinal) return a.constraint_ordinal < b.constraint_ordinal ? -1 : 1;
  if (a.code != b.code) return a.code < b.code ? -1 : 1;
  if (a.constraint != b.constraint) return a.constraint < b.constraint ? -1 : 1;
  if (a.family != b.family) return a.family < b.family ? -1 : 1;
  if (a.subject_kind != b.subject_kind) return a.subject_kind < b.subject_kind ? -1 : 1;
  if (a.subject != b.subject) return a.subject < b.subject ? -1 : 1;
  if (a.expected != b.expected) return a.expected < b.expected ? -1 : 1;
  if (a.actual != b.actual) return a.actual < b.actual ? -1 : 1;
  return 0;
}

bool reason_less(const Reason& a, const Reason& b) noexcept { return compare_reason(a, b) < 0; }

std::string describe(const Reason& reason) {
  std::string text = to_string(reason.code);
  text += " [class=";
  text += to_string(reason.reason_class);
  text += ", constraint=";
  text += to_string(reason.constraint);
  text += " (";
  text += to_string(reason.constraint_kind);
  text += "), family=";
  text += to_string(reason.family);
  text += ", subject=";
  text += to_string(reason.subject_kind);
  text += ":";
  text += std::to_string(reason.subject);
  text += ", expected=";
  text += std::to_string(reason.expected);
  text += ", actual=";
  text += std::to_string(reason.actual);
  text += "]";
  return text;
}

Digest256 evaluation_digest(const EvaluationRecord& record) {
  SemanticHasher hasher;
  hasher.begin("crf.evaluation.v1");
  hasher.put_u64(record.id.value());
  hasher.put_u64(record.generation.value());
  hasher.put_u64(record.set_id.value());
  hasher.put_u64(record.set_generation.value());
  hasher.put_u64(record.path.value());
  hasher.put_u64(record.authority_generation.value());
  hasher.put_u16(static_cast<std::uint16_t>(record.outcome));
  hasher.put_u16(static_cast<std::uint16_t>(record.primary_reason));
  hasher.put_u8(static_cast<std::uint8_t>(record.state));
  hasher.put_bool(record.reasons_truncated);
  hasher.put_u32(static_cast<std::uint32_t>(record.reasons.size()));
  for (const Reason& reason : record.reasons) {
    hasher.put_u16(static_cast<std::uint16_t>(reason.code));
    hasher.put_u8(static_cast<std::uint8_t>(reason.reason_class));
    hasher.put_u64(reason.constraint.value());
    hasher.put_u16(static_cast<std::uint16_t>(reason.constraint_kind));
    hasher.put_u32(reason.constraint_ordinal);
    hasher.put_u8(static_cast<std::uint8_t>(reason.family));
    hasher.put_u8(static_cast<std::uint8_t>(reason.subject_kind));
    hasher.put_u64(reason.subject);
    hasher.put_u64(reason.expected);
    hasher.put_u64(reason.actual);
  }
  hasher.put_u32(static_cast<std::uint32_t>(record.preferences.size()));
  for (const PreferenceSlot& slot : record.preferences) {
    hasher.put_u64(slot.constraint.value());
    hasher.put_u16(static_cast<std::uint16_t>(slot.kind));
    hasher.put_u32(slot.constraint_ordinal);
    hasher.put_u32(slot.rank);
    hasher.put_u32(slot.weight);
    hasher.put_bool(slot.satisfied);
    hasher.put_i64(slot.margin);
  }
  feed_evidence(hasher, record.evidence);
  hasher.put_u32(record.consulted);
  // Provenance is deliberately excluded: epoch, publisher, boot and attempt are
  // authority metadata, and two evaluations of identical semantics must digest
  // identically regardless of which authorized publisher produced them.
  return hasher.finish();
}

ConstraintEvaluationId derived_evaluation_id(const ConstraintSetId& set_id,
                                             const ConstraintSetGeneration& set_generation,
                                             const PathId& path,
                                             const PathAuthorityGeneration& authority_generation,
                                             const EvidenceGenerationSet& evidence) {
  SemanticHasher hasher;
  hasher.begin("crf.evaluation-id.v1");
  hasher.put_u64(set_id.value());
  hasher.put_u64(set_generation.value());
  hasher.put_u64(path.value());
  hasher.put_u64(authority_generation.value());
  feed_evidence(hasher, evidence);
  const Digest256 digest = hasher.finish();
  const std::uint64_t derived = digest.leading_u64();
  return ConstraintEvaluationId::from_value(derived == 0 ? 1u : derived);
}

RouteFabricHandoff handoff_of(const EvaluationRecord& record) {
  RouteFabricHandoff handoff;
  handoff.set_id = record.set_id;
  handoff.set_generation = record.set_generation;
  handoff.path = record.path;
  handoff.authority_generation = record.authority_generation;
  handoff.evaluation_id = record.id;
  handoff.evaluation_generation = record.generation;
  handoff.outcome = record.outcome;
  handoff.evidence = record.evidence;
  handoff.digest = record.digest;
  return handoff;
}

const char* to_string(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::Admissible: return "ADMISSIBLE";
    case Outcome::AdmissibleWithPreferences: return "ADMISSIBLE_WITH_PREFERENCES";
    case Outcome::HardConstraintFailed: return "HARD_CONSTRAINT_FAILED";
    case Outcome::UnknownRequiredEvidence: return "UNKNOWN_REQUIRED_EVIDENCE";
    case Outcome::StalePathAuthority: return "STALE_PATH_AUTHORITY";
    case Outcome::StaleConstraintSet: return "STALE_CONSTRAINT_SET";
    case Outcome::StaleEvidence: return "STALE_EVIDENCE";
    case Outcome::RevalidationRequired: return "REVALIDATION_REQUIRED";
    case Outcome::Unauthorized: return "UNAUTHORIZED";
    case Outcome::ResourceLimit: return "RESOURCE_LIMIT";
    case Outcome::Malformed: return "MALFORMED";
  }
  return "UNKNOWN_OUTCOME";
}

const char* to_string(ReasonClass klass) noexcept {
  switch (klass) {
    case ReasonClass::ResourceAdmission: return "ResourceAdmission";
    case ReasonClass::WireDecode: return "WireDecode";
    case ReasonClass::CallerIdentity: return "CallerIdentity";
    case ReasonClass::EpochBootScope: return "EpochBootScope";
    case ReasonClass::ConstraintSetLifecycle: return "ConstraintSetLifecycle";
    case ReasonClass::PathAuthority: return "PathAuthority";
    case ReasonClass::EvidenceCurrentness: return "EvidenceCurrentness";
    case ReasonClass::MandatoryConstraint: return "MandatoryConstraint";
    case ReasonClass::Preference: return "Preference";
  }
  return "Unknown";
}

const char* to_string(SubjectKind kind) noexcept {
  switch (kind) {
    case SubjectKind::None: return "None";
    case SubjectKind::Constraint: return "Constraint";
    case SubjectKind::CandidatePath: return "CandidatePath";
    case SubjectKind::ConstraintSet: return "ConstraintSet";
    case SubjectKind::Node: return "Node";
    case SubjectKind::Link: return "Link";
    case SubjectKind::Tier: return "Tier";
    case SubjectKind::Site: return "Site";
    case SubjectKind::Capability: return "Capability";
    case SubjectKind::Policy: return "Policy";
    case SubjectKind::FailureDomain: return "FailureDomain";
    case SubjectKind::LocalityDomain: return "LocalityDomain";
    case SubjectKind::IsolationClass: return "IsolationClass";
    case SubjectKind::Publisher: return "Publisher";
    case SubjectKind::WorkerBoot: return "WorkerBoot";
    case SubjectKind::Coordinator: return "Coordinator";
  }
  return "Unknown";
}

const char* to_string(ResultState state) noexcept {
  switch (state) {
    case ResultState::Current: return "Current";
    case ResultState::Superseded: return "Superseded";
    case ResultState::RevalidationRequired: return "RevalidationRequired";
    case ResultState::RecoveredUnproven: return "RecoveredUnproven";
    case ResultState::StaleAtCommit: return "StaleAtCommit";
  }
  return "Unknown";
}

const char* to_string(BatchOutcome outcome) noexcept {
  switch (outcome) {
    case BatchOutcome::AdmissibleCandidatesAvailable: return "ADMISSIBLE_CANDIDATES_AVAILABLE";
    case BatchOutcome::NoAdmissibleCandidate: return "NO_ADMISSIBLE_CANDIDATE";
    case BatchOutcome::BatchRejected: return "BATCH_REJECTED";
  }
  return "Unknown";
}

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::None: return "NONE";
    case ReasonCode::ResourceLimitExceeded: return "RESOURCE_LIMIT_EXCEEDED";
    case ReasonCode::BatchTooLarge: return "BATCH_TOO_LARGE";
    case ReasonCode::TooManyConstraints: return "TOO_MANY_CONSTRAINTS";
    case ReasonCode::TooManyCandidates: return "TOO_MANY_CANDIDATES";
    case ReasonCode::TooManyEntityRefs: return "TOO_MANY_ENTITY_REFS";
    case ReasonCode::ExplanationTruncated: return "EXPLANATION_TRUNCATED";
    case ReasonCode::HistoryLimitReached: return "HISTORY_LIMIT_REACHED";
    case ReasonCode::MalformedFrame: return "MALFORMED_FRAME";
    case ReasonCode::UnsupportedProtocolVersion: return "UNSUPPORTED_PROTOCOL_VERSION";
    case ReasonCode::UnknownMessageId: return "UNKNOWN_MESSAGE_ID";
    case ReasonCode::TrailingBytes: return "TRAILING_BYTES";
    case ReasonCode::OversizedVector: return "OVERSIZED_VECTOR";
    case ReasonCode::IntegrityMismatch: return "INTEGRITY_MISMATCH";
    case ReasonCode::MalformedConstraint: return "MALFORMED_CONSTRAINT";
    case ReasonCode::MalformedCandidate: return "MALFORMED_CANDIDATE";
    case ReasonCode::UnsupportedVersion: return "UNSUPPORTED_VERSION";
    case ReasonCode::UnknownPublisher: return "UNKNOWN_PUBLISHER";
    case ReasonCode::PublisherNotRegistered: return "PUBLISHER_NOT_REGISTERED";
    case ReasonCode::SessionFenced: return "SESSION_FENCED";
    case ReasonCode::ScopeNotAuthorized: return "SCOPE_NOT_AUTHORIZED";
    case ReasonCode::MissingAuthorityContext: return "MISSING_AUTHORITY_CONTEXT";
    case ReasonCode::MutationAttemptConflict: return "MUTATION_ATTEMPT_CONFLICT";
    case ReasonCode::StaleCoordinatorEpoch: return "STALE_COORDINATOR_EPOCH";
    case ReasonCode::FutureCoordinatorEpoch: return "FUTURE_COORDINATOR_EPOCH";
    case ReasonCode::FencedWorkerBoot: return "FENCED_WORKER_BOOT";
    case ReasonCode::UnknownWorkerBoot: return "UNKNOWN_WORKER_BOOT";
    case ReasonCode::WorkerBootReused: return "WORKER_BOOT_REUSED";
    case ReasonCode::ConstraintSetNotFound: return "CONSTRAINT_SET_NOT_FOUND";
    case ReasonCode::ConstraintSetNotActive: return "CONSTRAINT_SET_NOT_ACTIVE";
    case ReasonCode::ConstraintSetSuspended: return "CONSTRAINT_SET_SUSPENDED";
    case ReasonCode::ConstraintSetRevalidationRequired: return "CONSTRAINT_SET_REVALIDATION_REQUIRED";
    case ReasonCode::ConstraintSetRevoked: return "CONSTRAINT_SET_REVOKED";
    case ReasonCode::ConstraintSetSuperseded: return "CONSTRAINT_SET_SUPERSEDED";
    case ReasonCode::ConstraintSetRetired: return "CONSTRAINT_SET_RETIRED";
    case ReasonCode::StaleConstraintSetGeneration: return "STALE_CONSTRAINT_SET_GENERATION";
    case ReasonCode::ContradictoryConstraintSet: return "CONTRADICTORY_CONSTRAINT_SET";
    case ReasonCode::PathAuthorityNotEvaluated: return "PATH_AUTHORITY_NOT_EVALUATED";
    case ReasonCode::PathNotLegal: return "PATH_NOT_LEGAL";
    case ReasonCode::StalePathAuthority: return "STALE_PATH_AUTHORITY";
    case ReasonCode::PathAuthorityGenerationMissing: return "PATH_AUTHORITY_GENERATION_MISSING";
    case ReasonCode::StaleTopologyEvidence: return "STALE_TOPOLOGY_EVIDENCE";
    case ReasonCode::StaleLinkStateEvidence: return "STALE_LINK_STATE_EVIDENCE";
    case ReasonCode::StaleCapabilityEvidence: return "STALE_CAPABILITY_EVIDENCE";
    case ReasonCode::StaleFailureDomainEvidence: return "STALE_FAILURE_DOMAIN_EVIDENCE";
    case ReasonCode::StalePolicyEvidence: return "STALE_POLICY_EVIDENCE";
    case ReasonCode::StalePlannerEvidence: return "STALE_PLANNER_EVIDENCE";
    case ReasonCode::EvidenceAgeExceeded: return "EVIDENCE_AGE_EXCEEDED";
    case ReasonCode::EvidenceNotBound: return "EVIDENCE_NOT_BOUND";
    case ReasonCode::PlannerCostModelMismatch: return "PLANNER_COST_MODEL_MISMATCH";
    case ReasonCode::UnknownRequiredEvidence: return "UNKNOWN_REQUIRED_EVIDENCE";
    case ReasonCode::MaxLatencyExceeded: return "MAX_LATENCY_EXCEEDED";
    case ReasonCode::LatencyEvidenceUnavailable: return "LATENCY_EVIDENCE_UNAVAILABLE";
    case ReasonCode::MinBandwidthCapabilityNotMet: return "MIN_BANDWIDTH_CAPABILITY_NOT_MET";
    case ReasonCode::BandwidthCapabilityUnavailable: return "BANDWIDTH_CAPABILITY_UNAVAILABLE";
    case ReasonCode::RequiredNodeAbsent: return "REQUIRED_NODE_ABSENT";
    case ReasonCode::ForbiddenNodePresent: return "FORBIDDEN_NODE_PRESENT";
    case ReasonCode::RequiredLinkAbsent: return "REQUIRED_LINK_ABSENT";
    case ReasonCode::ForbiddenLinkPresent: return "FORBIDDEN_LINK_PRESENT";
    case ReasonCode::RequiredTierNotMet: return "REQUIRED_TIER_NOT_MET";
    case ReasonCode::ForbiddenTierPresent: return "FORBIDDEN_TIER_PRESENT";
    case ReasonCode::RequiredSiteNotMet: return "REQUIRED_SITE_NOT_MET";
    case ReasonCode::ForbiddenSitePresent: return "FORBIDDEN_SITE_PRESENT";
    case ReasonCode::LocalityScopeViolated: return "LOCALITY_SCOPE_VIOLATED";
    case ReasonCode::IsolationClassNotProven: return "ISOLATION_CLASS_NOT_PROVEN";
    case ReasonCode::RequiredCapabilityMissing: return "REQUIRED_CAPABILITY_MISSING";
    case ReasonCode::ForbiddenCapabilityPresent: return "FORBIDDEN_CAPABILITY_PRESENT";
    case ReasonCode::RequiredFailureDomainRelationNotMet: return "REQUIRED_FAILURE_DOMAIN_RELATION_NOT_MET";
    case ReasonCode::ForbiddenFailureDomainRelationMet: return "FORBIDDEN_FAILURE_DOMAIN_RELATION_MET";
    case ReasonCode::AdministrativePolicyNotSatisfied: return "ADMINISTRATIVE_POLICY_NOT_SATISFIED";
    case ReasonCode::MaxHopCountExceeded: return "MAX_HOP_COUNT_EXCEEDED";
    case ReasonCode::TierEvidenceUnavailable: return "TIER_EVIDENCE_UNAVAILABLE";
    case ReasonCode::SiteEvidenceUnavailable: return "SITE_EVIDENCE_UNAVAILABLE";
    case ReasonCode::LocalityEvidenceUnavailable: return "LOCALITY_EVIDENCE_UNAVAILABLE";
    case ReasonCode::IsolationEvidenceUnavailable: return "ISOLATION_EVIDENCE_UNAVAILABLE";
    case ReasonCode::CapabilityEvidenceUnavailable: return "CAPABILITY_EVIDENCE_UNAVAILABLE";
    case ReasonCode::FailureDomainEvidenceUnavailable: return "FAILURE_DOMAIN_EVIDENCE_UNAVAILABLE";
    case ReasonCode::PolicyEvidenceUnavailable: return "POLICY_EVIDENCE_UNAVAILABLE";
  }
  return "UNKNOWN_REASON";
}

void encode_provenance(ByteWriter& writer, const Provenance& provenance) {
  writer.put_u64(provenance.epoch.value());
  writer.put_u64(provenance.publisher.value());
  writer.put_u64(provenance.worker_boot.value());
  writer.put_u64(provenance.attempt.value());
  writer.put_u64(provenance.request.value());
}

bool decode_provenance(ByteReader& reader, Provenance& out) {
  std::uint64_t epoch = 0;
  std::uint64_t publisher = 0;
  std::uint64_t boot = 0;
  std::uint64_t attempt = 0;
  std::uint64_t request = 0;
  if (!reader.u64(epoch) || !reader.u64(publisher) || !reader.u64(boot) || !reader.u64(attempt) ||
      !reader.u64(request)) {
    return false;
  }
  if (epoch != 0 && !CoordinatorEpoch::is_representable(epoch)) {
    reader.fail();
    return false;
  }
  out.epoch = epoch == 0 ? CoordinatorEpoch{} : CoordinatorEpoch::from_value(epoch);
  out.publisher = PublisherId::from_value(publisher);
  out.worker_boot = WorkerBootId::from_value(boot);
  out.attempt = MutationAttemptId::from_value(attempt);
  out.request = RequestId::from_value(request);
  return true;
}

void encode_evaluation(ByteWriter& writer, const EvaluationRecord& record) {
  writer.put_u64(record.id.value());
  writer.put_u64(record.generation.value());
  writer.put_u64(record.set_id.value());
  writer.put_u64(record.set_generation.value());
  writer.put_u64(record.path.value());
  writer.put_u64(record.authority_generation.value());
  writer.put_u16(static_cast<std::uint16_t>(record.outcome));
  writer.put_u16(static_cast<std::uint16_t>(record.primary_reason));
  writer.put_u8(static_cast<std::uint8_t>(record.state));
  writer.put_bool(record.reasons_truncated);
  writer.put_u64(record.committed_tick);
  encode_provenance(writer, record.provenance);
  write_evidence(writer, record.evidence);
  writer.put_u32(static_cast<std::uint32_t>(record.reasons.size()));
  for (const Reason& reason : record.reasons) {
    writer.put_u16(static_cast<std::uint16_t>(reason.code));
    writer.put_u8(static_cast<std::uint8_t>(reason.reason_class));
    writer.put_u8(static_cast<std::uint8_t>(reason.family));
    writer.put_u8(static_cast<std::uint8_t>(reason.subject_kind));
    writer.put_u8(0);
    writer.put_u64(reason.constraint.value());
    writer.put_u16(static_cast<std::uint16_t>(reason.constraint_kind));
    writer.put_u16(0);
    writer.put_u32(reason.constraint_ordinal);
    writer.put_u64(reason.subject);
    writer.put_u64(reason.expected);
    writer.put_u64(reason.actual);
  }
  writer.put_u32(static_cast<std::uint32_t>(record.preferences.size()));
  for (const PreferenceSlot& slot : record.preferences) {
    writer.put_u64(slot.constraint.value());
    writer.put_u16(static_cast<std::uint16_t>(slot.kind));
    writer.put_u16(0);
    writer.put_u32(slot.constraint_ordinal);
    writer.put_u32(slot.rank);
    writer.put_u32(slot.weight);
    writer.put_bool(slot.satisfied);
    writer.put_i64(slot.margin);
  }
  writer.put_u32(record.consulted);
  const std::span<const std::byte> digest_bytes(record.digest.data(), Digest256::kSize);
  writer.put_raw(digest_bytes);
}

bool decode_evaluation(ByteReader& reader, const Limits& limits, EvaluationRecord& out) {
  std::uint64_t id = 0;
  std::uint64_t generation = 0;
  std::uint64_t set_id = 0;
  std::uint64_t set_generation = 0;
  std::uint64_t path = 0;
  std::uint64_t authority_generation = 0;
  std::uint16_t outcome = 0;
  std::uint16_t primary = 0;
  std::uint8_t state = 0;
  if (!reader.u64(id) || !reader.u64(generation) || !reader.u64(set_id) ||
      !reader.u64(set_generation) || !reader.u64(path) || !reader.u64(authority_generation) ||
      !reader.u16(outcome) || !reader.u16(primary) || !reader.u8(state) ||
      !reader.boolean(out.reasons_truncated) || !reader.u64(out.committed_tick)) {
    return false;
  }
  // Identity and generation fields are strict: a zero or unrepresentable value
  // in durable state is corruption, never a default.
  if (id == 0 || !EvaluationGeneration::is_representable(generation) || set_id == 0 ||
      !ConstraintSetGeneration::is_representable(set_generation) || path == 0 ||
      !PathAuthorityGeneration::is_representable(authority_generation) || !known_outcome(outcome) ||
      !known_result_state(state)) {
    reader.fail();
    return false;
  }
  if (!decode_provenance(reader, out.provenance) || !read_evidence(reader, out.evidence)) {
    return false;
  }
  out.id = ConstraintEvaluationId::from_value(id);
  out.generation = EvaluationGeneration::from_value(generation);
  out.set_id = ConstraintSetId::from_value(set_id);
  out.set_generation = ConstraintSetGeneration::from_value(set_generation);
  out.path = PathId::from_value(path);
  out.authority_generation = PathAuthorityGeneration::from_value(authority_generation);
  out.outcome = static_cast<Outcome>(outcome);
  out.state = static_cast<ResultState>(state);

  std::uint32_t reason_count = 0;
  if (!reader.bounded_length(limits.max_explanation_reasons, reason_count)) {
    return false;
  }
  out.reasons.clear();
  out.reasons.reserve(reason_count);
  Reason previous{};
  bool has_previous = false;
  for (std::uint32_t index = 0; index < reason_count; ++index) {
    std::uint16_t code = 0;
    std::uint8_t klass = 0;
    std::uint8_t family = 0;
    std::uint8_t subject_kind = 0;
    std::uint8_t padding = 0;
    std::uint64_t constraint = 0;
    std::uint16_t constraint_kind = 0;
    std::uint16_t constraint_padding = 0;
    Reason reason;
    if (!reader.u16(code) || !reader.u8(klass) || !reader.u8(family) || !reader.u8(subject_kind) ||
        !reader.u8(padding) || !reader.u64(constraint) || !reader.u16(constraint_kind) ||
        !reader.u16(constraint_padding) || !reader.u32(reason.constraint_ordinal) ||
        !reader.u64(reason.subject) || !reader.u64(reason.expected) || !reader.u64(reason.actual)) {
      return false;
    }
    if (padding != 0 || constraint_padding != 0 || !known_reason_class(klass) ||
        !known_subject_kind(subject_kind) || !known_evidence_family(family) ||
        !known_constraint_kind(constraint_kind)) {
      reader.fail();
      return false;
    }
    reason.code = static_cast<ReasonCode>(code);
    reason.reason_class = static_cast<ReasonClass>(klass);
    reason.family = static_cast<EvidenceFamily>(family);
    reason.subject_kind = static_cast<SubjectKind>(subject_kind);
    reason.constraint = ConstraintId::from_value(constraint);
    reason.constraint_kind = static_cast<ConstraintKind>(constraint_kind);
    // The stored class must agree with the class implied by the code: a
    // malformed reason vector is rejected rather than trusted.
    if (reason_class_of(reason.code) != reason.reason_class) {
      reader.fail();
      return false;
    }
    if (has_previous && !reason_less(previous, reason)) {
      reader.fail();
      return false;
    }
    previous = reason;
    has_previous = true;
    out.reasons.push_back(reason);
  }
  if (reason_count != 0 && primary != static_cast<std::uint16_t>(out.reasons.front().code)) {
    reader.fail();
    return false;
  }
  out.primary_reason = static_cast<ReasonCode>(primary);
  if (out.reasons.empty() && out.primary_reason != ReasonCode::None) {
    reader.fail();
    return false;
  }

  std::uint32_t preference_count = 0;
  if (!reader.bounded_length(limits.max_constraints_per_set, preference_count)) {
    return false;
  }
  out.preferences.clear();
  out.preferences.reserve(preference_count);
  for (std::uint32_t index = 0; index < preference_count; ++index) {
    PreferenceSlot slot;
    std::uint16_t kind = 0;
    std::uint16_t padding = 0;
    std::uint64_t constraint = 0;
    if (!reader.u64(constraint) || !reader.u16(kind) || !reader.u16(padding) ||
        !reader.u32(slot.constraint_ordinal) || !reader.u32(slot.rank) || !reader.u32(slot.weight) ||
        !reader.boolean(slot.satisfied) || !reader.i64(slot.margin)) {
      return false;
    }
    if (padding != 0 || !known_constraint_kind(kind)) {
      reader.fail();
      return false;
    }
    slot.constraint = ConstraintId::from_value(constraint);
    slot.kind = static_cast<ConstraintKind>(kind);
    out.preferences.push_back(slot);
  }
  if (!reader.u32(out.consulted)) {
    return false;
  }
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes))) {
    return false;
  }
  out.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  return true;
}

}  // namespace crf
