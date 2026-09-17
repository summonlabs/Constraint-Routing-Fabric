// Constraint Routing Fabric -- coordinator: authority, two-phase evaluation, durability.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_COORDINATOR_HPP
#define CONSTRAINT_ROUTING_FABRIC_COORDINATOR_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/invalidation.hpp"
#include "constraint_routing_fabric/persistence.hpp"
#include "constraint_routing_fabric/snapshot.hpp"
#include "constraint_routing_fabric/status.hpp"
#include "constraint_routing_fabric/time.hpp"

namespace crf {

/// Out-of-band authority grant. Registration is default-deny: a publisher that
/// has no grant can never register, and a grant only permits registration with
/// the listed scopes. This runtime provides no cryptographic authentication, so
/// the grant list is the entire authorization surface.
struct PublisherGrant {
  PublisherId publisher{};
  AuthorityScopeMask scopes{0};
};

struct CoordinatorConfig {
  Limits limits{};
  std::string store_path{};
  std::vector<PublisherGrant> grants{};
  /// Creates a fresh store when none exists or the existing one is unreadable.
  /// The unreadable file is quarantined, never silently discarded.
  bool allow_initialize{true};
  /// Current authoritative evidence generations.
  EvidenceRequirements evidence{};
  std::uint32_t max_candidate_populations{16};
};

/// Why a stored result is no longer current. Every cause is reported explicitly.
enum class CurrentnessCause : std::uint8_t {
  None = 0,
  ConstraintSetStateChanged = 1,
  ConstraintSetSuperseded = 2,
  ConstraintSetGenerationAdvanced = 3,
  PathAuthorityAdvanced = 4,
  TopologyAdvanced = 5,
  LinkStateAdvanced = 6,
  CapabilityAdvanced = 7,
  FailureDomainAdvanced = 8,
  PolicyAdvanced = 9,
  PlannerAdvanced = 10,
  EvidenceRequirementChanged = 11,
  DependencyInvalidated = 12,
  EpochAdvanced = 13,
  RecoveredUnproven = 14,
  NoCurrentResult = 15,
};

[[nodiscard]] const char* to_string(CurrentnessCause cause) noexcept;

struct CurrentnessReport {
  ConstraintSetId set_id{};
  ConstraintSetGeneration set_generation{};
  ConstraintSetState state{ConstraintSetState::Declared};
  EvaluationGeneration evaluation_generation{};
  EvidenceRequirements required_evidence{};
  EvidenceRequirements published_evidence{};
  std::size_t current_results{0};
  std::size_t revalidation_required{0};
  std::size_t recovered_unproven{0};
  bool publisher_authority_live{false};
  std::vector<CurrentnessCause> causes{};
};

/// Result of a two-phase evaluation attempt.
struct CommitOutcome {
  EvaluationBatch batch{};
  bool committed{false};
  ReasonCode rejection_reason{ReasonCode::None};
  /// The dependency mask captured before phase one and re-read at commit time.
  /// A mismatch between them is exactly the race the two-phase commit closes.
  EvidenceFamilyMask dependency_mask_at_snapshot{0};
  EvidenceFamilyMask dependency_mask_at_commit{0};
};

/// Observable phases of the two-phase commit, used by deterministic race tests.
enum class CoordinatorPhase : std::uint8_t {
  AfterDependencySnapshot = 1,
  BeforeCommitVerification = 2,
  AfterCommit = 3,
};

using PhaseHook = std::function<void(CoordinatorPhase)>;

/// The authoritative runtime. All mutating entry points first authorize the
/// caller, then de-duplicate the mutation attempt, then perform semantic work,
/// then persist, then publish. A request that requires durability is never
/// acknowledged before the durable write has succeeded.
class Coordinator {
 public:
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;
  ~Coordinator();

  [[nodiscard]] static Result<std::unique_ptr<Coordinator>> open(const CoordinatorConfig& config,
                                                                 Clock* clock);
  /// Opens without a durable store. Used only by tests that exercise in-memory
  /// semantics; every production path uses ::open.
  [[nodiscard]] static Result<std::unique_ptr<Coordinator>> open_in_memory(const CoordinatorConfig& config,
                                                                          Clock* clock);

  // --- authority ------------------------------------------------------------
  [[nodiscard]] Result<PublisherRegistration> register_publisher(const AuthorityContext& context,
                                                                 PublisherId publisher,
                                                                 WorkerBootId boot,
                                                                 AuthorityScopeMask scopes,
                                                                 SessionId session);
  [[nodiscard]] Status fence_boot(const AuthorityContext& context, WorkerBootId boot);
  /// Fences the boot that owns a session the coordinator observed to be lost.
  /// This is the coordinator acting on observed transport loss, not a caller
  /// request, so it is not gated on a publisher scope.
  [[nodiscard]] Status fence_on_session_loss(SessionId session);
  [[nodiscard]] Status drop_session(const AuthorityContext& context, SessionId session);
  [[nodiscard]] Result<ReplayVerdict> observe_attempt(const AuthorityContext& context,
                                                      const Digest256& payload);
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept;
  [[nodiscard]] const AuthorityRegistry& authority() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;
  [[nodiscard]] const EvidenceRequirements& evidence_requirements() const noexcept;
  [[nodiscard]] std::uint64_t now_ticks() const;

  // --- constraint set definitions ------------------------------------------
  [[nodiscard]] Result<ConstraintSet> publish_constraint_set(const AuthorityContext& context,
                                                             ConstraintSet set);
  [[nodiscard]] Result<ConstraintSet> apply_lifecycle(const AuthorityContext& context,
                                                      ConstraintSetId set_id,
                                                      LifecycleEvent event);
  [[nodiscard]] Result<ConstraintSet> get_constraint_set(ConstraintSetId set_id) const;
  [[nodiscard]] std::vector<ConstraintSetId> constraint_set_ids() const;

  // --- evidence generations -------------------------------------------------
  [[nodiscard]] Status set_evidence_requirements(const AuthorityContext& context,
                                                 EvidenceRequirements requirements);
  /// Advances one evidence family. The family watermark moves forward and the
  /// dependents of that family become revalidation-required. Unrelated
  /// evaluations are untouched.
  [[nodiscard]] Status advance_family(const AuthorityContext& context, EvidenceFamily family,
                                      std::uint64_t generation);
  /// Precise invalidation of one entity. Only evaluations that actually bound
  /// this key become revalidation-required.
  [[nodiscard]] Status invalidate_key(const AuthorityContext& context, const InvalidationKey& key);

  // --- evaluation -----------------------------------------------------------
  [[nodiscard]] Result<CommitOutcome> evaluate(const AuthorityContext& context, ConstraintSetId set_id,
                                               std::span<const CandidatePath> candidates,
                                               ConstraintSetGeneration expected_generation = {});
  /// Re-evaluates the retained candidate population of a set against current
  /// evidence. Used after invalidation and after conservative recovery.
  [[nodiscard]] Result<CommitOutcome> revalidate(const AuthorityContext& context, ConstraintSetId set_id);

  [[nodiscard]] Result<std::vector<RouteFabricHandoff>> handoffs(const AuthorityContext& context,
                                                                 ConstraintSetId set_id) const;
  [[nodiscard]] Result<EvaluationRecord> current_result(ConstraintSetId set_id, PathId path) const;
  [[nodiscard]] Result<CurrentnessReport> currentness(ConstraintSetId set_id) const;
  [[nodiscard]] Result<DefinitionsSnapshot> snapshot_definitions(ConstraintSetId set_id) const;
  [[nodiscard]] Result<ResultsSnapshot> snapshot_results(ConstraintSetId set_id) const;
  [[nodiscard]] Result<std::vector<CandidatePath>> retained_candidates(ConstraintSetId set_id) const;

  // --- diagnostics / test seams --------------------------------------------
  void set_phase_hook(PhaseHook hook);
  [[nodiscard]] std::size_t stored_evaluation_count() const noexcept;
  [[nodiscard]] std::size_t serialized_state_bytes() const;
  [[nodiscard]] const Watermarks& watermarks() const noexcept;
  [[nodiscard]] const InvalidationIndex& invalidation_index() const noexcept;
  /// Forces a durable write of the current state. Returns the store status.
  [[nodiscard]] Status flush();

 private:
  class Impl;
  explicit Coordinator(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_{};
};

[[nodiscard]] const char* to_string(CoordinatorPhase phase) noexcept;

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_COORDINATOR_HPP
