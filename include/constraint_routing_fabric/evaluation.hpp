// Constraint Routing Fabric -- evaluation outcomes, reasons and records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_EVALUATION_HPP
#define CONSTRAINT_ROUTING_FABRIC_EVALUATION_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"

namespace crf {

/// Result class of one candidate evaluation. Never a boolean.
enum class Outcome : std::uint16_t {
  Admissible = 0,
  AdmissibleWithPreferences = 1,
  HardConstraintFailed = 2,
  UnknownRequiredEvidence = 3,
  StalePathAuthority = 4,
  StaleConstraintSet = 5,
  StaleEvidence = 6,
  RevalidationRequired = 7,
  Unauthorized = 8,
  ResourceLimit = 9,
  Malformed = 10,
};

/// Precedence class. The documented evaluation precedence is exactly this
/// enumeration order: resource admission, wire/decode, caller identity,
/// epoch/boot/scope, constraint-set lifecycle, Path Authority generation,
/// mandatory evidence currentness, mandatory constraints in canonical order,
/// preference evaluation.
enum class ReasonClass : std::uint8_t {
  ResourceAdmission = 0,
  WireDecode = 1,
  CallerIdentity = 2,
  EpochBootScope = 3,
  ConstraintSetLifecycle = 4,
  PathAuthority = 5,
  EvidenceCurrentness = 6,
  MandatoryConstraint = 7,
  Preference = 8,
};

/// Deterministic machine-readable reason. Reasons are totally ordered so that
/// the primary reason of a multi-failure input never depends on container order.
enum class ReasonCode : std::uint16_t {
  None = 0,

  ResourceLimitExceeded = 100,
  BatchTooLarge = 101,
  TooManyConstraints = 102,
  TooManyCandidates = 103,
  TooManyEntityRefs = 104,
  ExplanationTruncated = 105,
  HistoryLimitReached = 106,

  MalformedFrame = 200,
  UnsupportedProtocolVersion = 201,
  UnknownMessageId = 202,
  TrailingBytes = 203,
  OversizedVector = 204,
  IntegrityMismatch = 205,
  MalformedConstraint = 206,
  MalformedCandidate = 207,
  UnsupportedVersion = 208,

  UnknownPublisher = 300,
  PublisherNotRegistered = 301,
  SessionFenced = 302,
  ScopeNotAuthorized = 303,
  MissingAuthorityContext = 304,
  MutationAttemptConflict = 305,

  StaleCoordinatorEpoch = 400,
  FutureCoordinatorEpoch = 401,
  FencedWorkerBoot = 402,
  UnknownWorkerBoot = 403,
  WorkerBootReused = 404,

  ConstraintSetNotFound = 500,
  ConstraintSetNotActive = 501,
  ConstraintSetSuspended = 502,
  ConstraintSetRevalidationRequired = 503,
  ConstraintSetRevoked = 504,
  ConstraintSetSuperseded = 505,
  ConstraintSetRetired = 506,
  StaleConstraintSetGeneration = 507,
  ContradictoryConstraintSet = 508,

  PathAuthorityNotEvaluated = 600,
  PathNotLegal = 601,
  StalePathAuthority = 602,
  PathAuthorityGenerationMissing = 603,

  StaleTopologyEvidence = 700,
  StaleLinkStateEvidence = 701,
  StaleCapabilityEvidence = 702,
  StaleFailureDomainEvidence = 703,
  StalePolicyEvidence = 704,
  StalePlannerEvidence = 705,
  EvidenceAgeExceeded = 706,
  EvidenceNotBound = 707,
  PlannerCostModelMismatch = 708,
  UnknownRequiredEvidence = 709,

  MaxLatencyExceeded = 800,
  LatencyEvidenceUnavailable = 801,
  MinBandwidthCapabilityNotMet = 802,
  BandwidthCapabilityUnavailable = 803,
  RequiredNodeAbsent = 804,
  ForbiddenNodePresent = 805,
  RequiredLinkAbsent = 806,
  ForbiddenLinkPresent = 807,
  RequiredTierNotMet = 808,
  ForbiddenTierPresent = 809,
  RequiredSiteNotMet = 810,
  ForbiddenSitePresent = 811,
  LocalityScopeViolated = 812,
  IsolationClassNotProven = 813,
  RequiredCapabilityMissing = 814,
  ForbiddenCapabilityPresent = 815,
  RequiredFailureDomainRelationNotMet = 816,
  ForbiddenFailureDomainRelationMet = 817,
  AdministrativePolicyNotSatisfied = 818,
  MaxHopCountExceeded = 819,
  TierEvidenceUnavailable = 820,
  SiteEvidenceUnavailable = 821,
  LocalityEvidenceUnavailable = 822,
  IsolationEvidenceUnavailable = 823,
  CapabilityEvidenceUnavailable = 824,
  FailureDomainEvidenceUnavailable = 825,
  PolicyEvidenceUnavailable = 826,
};

/// Typed subject of a reason, so explanations can render the exact entity.
enum class SubjectKind : std::uint8_t {
  None = 0,
  Constraint = 1,
  CandidatePath = 2,
  ConstraintSet = 3,
  Node = 4,
  Link = 5,
  Tier = 6,
  Site = 7,
  Capability = 8,
  Policy = 9,
  FailureDomain = 10,
  LocalityDomain = 11,
  IsolationClass = 12,
  Publisher = 13,
  WorkerBoot = 14,
  Coordinator = 15,
};

/// One deterministic reason. Value fields are integer identities only; there is
/// no dynamic text, so two semantically equal reasons always compare equal.
struct Reason {
  ReasonCode code{ReasonCode::None};
  ReasonClass reason_class{ReasonClass::ResourceAdmission};
  ConstraintId constraint{};
  ConstraintKind constraint_kind{ConstraintKind::Unset};
  std::uint32_t constraint_ordinal{0};
  EvidenceFamily family{EvidenceFamily::None};
  SubjectKind subject_kind{SubjectKind::None};
  std::uint64_t subject{0};
  std::uint64_t expected{0};
  std::uint64_t actual{0};
};

[[nodiscard]] ReasonClass reason_class_of(ReasonCode code) noexcept;
[[nodiscard]] Outcome outcome_of(ReasonCode code) noexcept;
[[nodiscard]] const char* to_string(ReasonCode code) noexcept;
[[nodiscard]] const char* to_string(Outcome outcome) noexcept;
[[nodiscard]] const char* to_string(ReasonClass klass) noexcept;
[[nodiscard]] const char* to_string(SubjectKind kind) noexcept;

/// Total order over reasons: class, canonical constraint ordinal, code,
/// constraint id, family, subject, expected, actual. Independent of insertion
/// order, so a multi-failure input always reports the same primary reason.
[[nodiscard]] int compare_reason(const Reason& a, const Reason& b) noexcept;
[[nodiscard]] bool reason_less(const Reason& a, const Reason& b) noexcept;

/// Deterministic human-readable rendering used by explanations and examples.
[[nodiscard]] std::string describe(const Reason& reason);

/// One preference slot of the documented preference vector.
struct PreferenceSlot {
  ConstraintId constraint{};
  ConstraintKind kind{ConstraintKind::Unset};
  std::uint32_t constraint_ordinal{0};
  std::uint32_t rank{0};
  std::uint32_t weight{0};
  bool satisfied{false};
  /// Signed advantage. Larger is better. Integer fixed point only.
  std::int64_t margin{0};
};

/// Where an evaluation result stands in the authoritative result index.
enum class ResultState : std::uint8_t {
  Current = 1,
  Superseded = 2,
  RevalidationRequired = 3,
  /// Restored from durable state after a restart and not yet re-proven.
  RecoveredUnproven = 4,
  /// Rejected at commit time because a dependency generation moved.
  StaleAtCommit = 5,
};

/// Authority provenance of a published fact or evaluation.
struct Provenance {
  CoordinatorEpoch epoch{};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  MutationAttemptId attempt{};
  RequestId request{};

  friend bool operator==(const Provenance& a, const Provenance& b) noexcept;
};

/// The complete, self-describing result of evaluating one candidate.
struct EvaluationRecord {
  ConstraintEvaluationId id{};
  EvaluationGeneration generation{};
  ConstraintSetId set_id{};
  ConstraintSetGeneration set_generation{};
  PathId path{};
  PathAuthorityGeneration authority_generation{};
  Outcome outcome{Outcome::Malformed};
  ReasonCode primary_reason{ReasonCode::None};
  std::vector<Reason> reasons{};
  std::vector<PreferenceSlot> preferences{};
  EvidenceGenerationSet evidence{};
  EvidenceFamilyMask consulted{0};
  Provenance provenance{};
  ResultState state{ResultState::Current};
  /// True when the bounded reason vector dropped reasons. The primary reason is
  /// always retained, so truncation never changes the outcome.
  bool reasons_truncated{false};
  std::uint64_t committed_tick{0};
  Digest256 digest{};
};

/// Immutable handoff to Route Fabric. Route Fabric owns route state; this
/// runtime only publishes an identity and an exact evidence binding.
struct RouteFabricHandoff {
  ConstraintSetId set_id{};
  ConstraintSetGeneration set_generation{};
  PathId path{};
  PathAuthorityGeneration authority_generation{};
  ConstraintEvaluationId evaluation_id{};
  EvaluationGeneration evaluation_generation{};
  Outcome outcome{Outcome::Malformed};
  EvidenceGenerationSet evidence{};
  Digest256 digest{};
};

[[nodiscard]] RouteFabricHandoff handoff_of(const EvaluationRecord& record);

/// Summary class of a whole evaluation batch.
enum class BatchOutcome : std::uint16_t {
  AdmissibleCandidatesAvailable = 0,
  NoAdmissibleCandidate = 1,
  BatchRejected = 2,
};

/// One entry of the deterministic admissible ordering.
struct RankedCandidate {
  PathId path{};
  std::uint32_t record_index{0};
};

struct EvaluationBatch {
  ConstraintSetId set_id{};
  ConstraintSetGeneration set_generation{};
  EvaluationGeneration generation{};
  BatchOutcome batch_outcome{BatchOutcome::BatchRejected};
  bool has_admissible{false};
  std::vector<EvaluationRecord> records{};
  std::vector<RankedCandidate> admissible_order{};
  ReasonCode primary_batch_reason{ReasonCode::None};
};

[[nodiscard]] const char* to_string(BatchOutcome outcome) noexcept;
[[nodiscard]] const char* to_string(ResultState state) noexcept;

/// Semantic digest of an evaluation record. Timestamps, socket identities,
/// thread identities and diagnostic counters are excluded.
[[nodiscard]] Digest256 evaluation_digest(const EvaluationRecord& record);

/// Deterministic evaluation identity derived from the semantic binding.
[[nodiscard]] ConstraintEvaluationId derived_evaluation_id(const ConstraintSetId& set_id,
                                                           const ConstraintSetGeneration& set_generation,
                                                           const PathId& path,
                                                           const PathAuthorityGeneration& authority_generation,
                                                           const EvidenceGenerationSet& evidence);

/// True when the two evaluations bind exactly the same evidence generations.
[[nodiscard]] bool same_evidence_binding(const EvidenceGenerationSet& a,
                                         const EvidenceGenerationSet& b) noexcept;

void encode_evaluation(ByteWriter& writer, const EvaluationRecord& record);
[[nodiscard]] bool decode_evaluation(ByteReader& reader, const Limits& limits, EvaluationRecord& out);
void encode_provenance(ByteWriter& writer, const Provenance& provenance);
[[nodiscard]] bool decode_provenance(ByteReader& reader, Provenance& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_EVALUATION_HPP
