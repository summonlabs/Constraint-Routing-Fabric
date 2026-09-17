// Constraint Routing Fabric -- coordinator implementation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/coordinator.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <set>
#include <set>
#include <string>
#include <utility>

#include "constraint_routing_fabric/evaluator.hpp"
#include "constraint_routing_fabric/ordering.hpp"

namespace crf {
namespace {

[[nodiscard]] EvidenceFamilyMask families_of(const Constraint& constraint) noexcept {
  if (constraint.kind == ConstraintKind::MaxLatency) {
    return constraint.latency_source == LatencySource::PlannerCost
               ? family_bit(EvidenceFamily::Planner)
               : family_bit(EvidenceFamily::LinkState);
  }
  return evidence_families(constraint.kind);
}

[[nodiscard]] EvidenceFamilyMask consulted_mask(const ConstraintSet& set) noexcept {
  EvidenceFamilyMask mask = 0;
  for (const Constraint& constraint : set.constraints) {
    mask |= families_of(constraint);
  }
  mask |= family_bit(EvidenceFamily::PathAuthority);
  if (set.ranking.consume_planner_cost) {
    mask |= family_bit(EvidenceFamily::Planner);
  }
  return mask;
}

[[nodiscard]] std::uint64_t generation_for(const EvidenceRequirements& evidence,
                                           EvidenceFamily family) noexcept {
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

[[nodiscard]] bool evidence_equal(const EvidenceRequirements& a, const EvidenceRequirements& b) noexcept {
  return a.topology == b.topology && a.link_state == b.link_state && a.capability == b.capability &&
         a.failure_domain == b.failure_domain && a.policy == b.policy && a.planner == b.planner &&
         a.path_authority == b.path_authority && a.max_evidence_age_ticks == b.max_evidence_age_ticks;
}

[[nodiscard]] std::uint64_t request_digest(std::span<const CandidatePath> candidates,
                                           const ConstraintSetId& set_id,
                                           const ConstraintSetGeneration& generation) {
  SemanticHasher hasher;
  hasher.begin("crf.evaluation-request.v1");
  hasher.put_u64(set_id.value());
  hasher.put_u64(generation.value());
  hasher.put_u32(static_cast<std::uint32_t>(candidates.size()));
  for (const CandidatePath& candidate : candidates) {
    hasher.put_u64(candidate.path.value());
    hasher.put_digest(candidate_digest(candidate));
  }
  return hasher.finish().leading_u64();
}

[[nodiscard]] ReasonCode staleness_reason(EvidenceFamily family) noexcept {
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

constexpr std::array<EvidenceFamily, 7> kFamilies = {
    EvidenceFamily::Topology,      EvidenceFamily::LinkState,     EvidenceFamily::Capability,
    EvidenceFamily::FailureDomain, EvidenceFamily::Policy,        EvidenceFamily::Planner,
    EvidenceFamily::PathAuthority};

}  // namespace

const char* to_string(CurrentnessCause cause) noexcept {
  switch (cause) {
    case CurrentnessCause::None: return "None";
    case CurrentnessCause::ConstraintSetStateChanged: return "ConstraintSetStateChanged";
    case CurrentnessCause::ConstraintSetSuperseded: return "ConstraintSetSuperseded";
    case CurrentnessCause::ConstraintSetGenerationAdvanced: return "ConstraintSetGenerationAdvanced";
    case CurrentnessCause::PathAuthorityAdvanced: return "PathAuthorityAdvanced";
    case CurrentnessCause::TopologyAdvanced: return "TopologyAdvanced";
    case CurrentnessCause::LinkStateAdvanced: return "LinkStateAdvanced";
    case CurrentnessCause::CapabilityAdvanced: return "CapabilityAdvanced";
    case CurrentnessCause::FailureDomainAdvanced: return "FailureDomainAdvanced";
    case CurrentnessCause::PolicyAdvanced: return "PolicyAdvanced";
    case CurrentnessCause::PlannerAdvanced: return "PlannerAdvanced";
    case CurrentnessCause::EvidenceRequirementChanged: return "EvidenceRequirementChanged";
    case CurrentnessCause::DependencyInvalidated: return "DependencyInvalidated";
    case CurrentnessCause::EpochAdvanced: return "EpochAdvanced";
    case CurrentnessCause::RecoveredUnproven: return "RecoveredUnproven";
    case CurrentnessCause::NoCurrentResult: return "NoCurrentResult";
  }
  return "Unknown";
}

const char* to_string(CoordinatorPhase phase) noexcept {
  switch (phase) {
    case CoordinatorPhase::AfterDependencySnapshot: return "AfterDependencySnapshot";
    case CoordinatorPhase::BeforeCommitVerification: return "BeforeCommitVerification";
    case CoordinatorPhase::AfterCommit: return "AfterCommit";
  }
  return "Unknown";
}

class Coordinator::Impl {
 public:
  CoordinatorConfig config{};
  Clock* clock{nullptr};
  std::unique_ptr<DurableStore> store{};
  AuthorityRegistry authority{};
  EvidenceRequirements evidence{};
  Watermarks watermarks{};
  std::vector<ConstraintSet> sets{};
  std::vector<EvaluationRecord> evaluations{};
  std::vector<CandidatePopulation> populations{};
  std::map<std::pair<std::uint64_t, std::uint64_t>, ConstraintEvaluationId> current{};
  InvalidationIndex index{};
  EvaluationGeneration last_generation{};
  std::uint64_t invalidation_sequence{0};
  mutable std::mutex mutex{};
  PhaseHook hook{};
  bool durable{false};

  [[nodiscard]] std::uint64_t now() const { return clock->now_ticks(); }

  /// Projects the live authority registry into the durable view. Fenced boots
  /// and the boots that currently hold live authority are both recorded, so a
  /// later restart can fence every boot of this coordinator incarnation.
  void refresh_authority_projection(PersistentState& state) {
    state.fenced_boots.clear();
    for (const auto& entry : authority.fenced()) {
      state.fenced_boots.push_back(entry.second);
    }
    state.live_boots.clear();
    std::set<WorkerBootId> seen;
    for (const PublisherRegistration& registration : authority.registrations()) {
      if (registration.live && seen.insert(registration.boot).second) {
        state.live_boots.push_back(registration.boot);
      }
    }
  }

  [[nodiscard]] PersistentState to_state() {
    PersistentState state;
    state.epoch = authority.epoch();
    state.evidence = evidence;
    state.watermarks = watermarks;
    state.sets = sets;
    state.evaluations = evaluations;
    state.populations = populations;
    state.attempts = authority.attempts();
    state.last_evaluation_generation = last_generation;
    state.initialized = true;
    refresh_authority_projection(state);
    return state;
  }

  void apply_state(const PersistentState& state) {
    evidence = state.evidence;
    watermarks = state.watermarks;
    sets = state.sets;
    evaluations = state.evaluations;
    populations = state.populations;
    last_generation = state.last_evaluation_generation;
    rebuild_derived();
  }

  void rebuild_derived() {
    current.clear();
    index.clear();
    const Limits& limits = config.limits;
    for (const EvaluationRecord& record : evaluations) {
      if (record.state != ResultState::Current) {
        continue;
      }
      current[std::make_pair(record.set_id.value(), record.path.value())] = record.id;
      const ConstraintSet* set = find_set(record.set_id);
      if (set == nullptr) {
        continue;
      }
      const CandidatePath* candidate = find_candidate(record.set_id, record.path);
      if (candidate == nullptr) {
        continue;
      }
      const std::vector<InvalidationKey> keys =
          dependency_keys(record, *set, *candidate, limits);
      for (const InvalidationKey& key : keys) {
        (void)index.bind(key, record.id);
      }
    }
  }

  [[nodiscard]] const ConstraintSet* find_set(const ConstraintSetId& id) const {
    for (const ConstraintSet& set : sets) {
      if (set.id == id) {
        return &set;
      }
    }
    return nullptr;
  }

  [[nodiscard]] ConstraintSet* find_set_mutable(const ConstraintSetId& id) {
    for (ConstraintSet& set : sets) {
      if (set.id == id) {
        return &set;
      }
    }
    return nullptr;
  }

  [[nodiscard]] const CandidatePath* find_candidate(const ConstraintSetId& set_id,
                                                    const PathId& path) const {
    for (const CandidatePopulation& population : populations) {
      if (!(population.set_id == set_id)) {
        continue;
      }
      for (const CandidatePath& candidate : population.candidates) {
        if (candidate.path == path) {
          return &candidate;
        }
      }
    }
    return nullptr;
  }

  void trim_history() {
    const std::size_t limit = config.limits.max_evaluations_retained;
    while (evaluations.size() > limit) {
      std::size_t victim = evaluations.size();
      EvaluationGeneration oldest;
      for (std::size_t position = 0; position < evaluations.size(); ++position) {
        if (evaluations[position].state == ResultState::Current) {
          continue;
        }
        if (victim == evaluations.size() || evaluations[position].generation < oldest) {
          victim = position;
          oldest = evaluations[position].generation;
        }
      }
      if (victim == evaluations.size()) {
        return;
      }
      evaluations.erase(evaluations.begin() + static_cast<std::ptrdiff_t>(victim));
    }
  }

  void mark_revalidation_required(const std::set<ConstraintEvaluationId>& targets) {
    if (targets.empty()) {
      return;
    }
    for (EvaluationRecord& record : evaluations) {
      if (targets.find(record.id) != targets.end()) {
        record.state = ResultState::RevalidationRequired;
      }
    }
  }

  /// Applies an evidence-requirement change. The caller must hold the lock:
  /// this is the shared body of set_evidence_requirements and advance_family,
  /// which would otherwise re-enter the non-recursive coordinator mutex.
  [[nodiscard]] Status apply_evidence_requirements(const AuthorityContext& context,
                                                   const EvidenceRequirements& requirements) {
    const Status authorized = authority.authorize(context, scope_bit(AuthorityScope::PublishEvaluation));
    if (!authorized.ok()) {
      return authorized;
    }
    const Result<ReplayVerdict> replay = authority.observe_attempt(
        context.attempt,
        digest_of("crf.evidence-requirements.v1", [&](SemanticHasher& hasher) {
          hasher.put_u64(requirements.topology.value());
          hasher.put_u64(requirements.link_state.value());
          hasher.put_u64(requirements.capability.value());
          hasher.put_u64(requirements.failure_domain.value());
          hasher.put_u64(requirements.policy.value());
          hasher.put_u64(requirements.planner.value());
          hasher.put_u64(requirements.path_authority.value());
          hasher.put_u64(requirements.max_evidence_age_ticks);
        }),
        now(), config.limits);
    if (!replay.ok()) {
      return Status::failure(replay.code(), replay.detail());
    }
    if (replay.value() == ReplayVerdict::Conflict) {
      return Status::failure(ErrorCode::MutationAttemptConflict,
                             "mutation attempt identity was reused with a different payload");
    }
    if (replay.value() == ReplayVerdict::ExactReplay) {
      return Status::success();
    }

    std::vector<EvidenceFamily> advanced;
    for (const EvidenceFamily family : kFamilies) {
      const std::uint64_t current_value = generation_for(evidence, family);
      const std::uint64_t next_value = generation_for(requirements, family);
      if (next_value < current_value) {
        return Status::failure(ErrorCode::StaleGeneration, "evidence generations never decrease");
      }
      if (next_value > current_value) {
        advanced.push_back(family);
      }
    }

    PersistentState next = to_state();
    next.evidence = requirements;
    std::set<ConstraintEvaluationId> dependents;
    for (const EvidenceFamily family : advanced) {
      if (!watermarks.advance_family(family, generation_for(requirements, family))) {
        return Status::failure(ErrorCode::StaleGeneration, "evidence watermark never decreases");
      }
      for (const ConstraintEvaluationId& id : dependents_of_family(family)) {
        dependents.insert(id);
      }
    }
    next.watermarks = watermarks;
    for (EvaluationRecord& record : next.evaluations) {
      if (dependents.find(record.id) != dependents.end() && record.state == ResultState::Current) {
        record.state = ResultState::RevalidationRequired;
      }
    }
    const Status persisted = persist(next);
    if (!persisted.ok()) {
      return persisted;
    }
    apply_state(next);
    return Status::success();
  }

  [[nodiscard]] Status persist(const PersistentState& state) {
    if (!durable || store == nullptr) {
      return Status::success();
    }
    return store->save(state);
  }

  [[nodiscard]] std::vector<ConstraintEvaluationId> dependents_of(
      const std::vector<InvalidationKey>& keys) const {
    std::set<ConstraintEvaluationId> found;
    for (const InvalidationKey& key : keys) {
      for (const ConstraintEvaluationId& id : index.dependents(key)) {
        found.insert(id);
      }
    }
    return std::vector<ConstraintEvaluationId>(found.begin(), found.end());
  }

  [[nodiscard]] std::vector<ConstraintEvaluationId> dependents_of_family(EvidenceFamily family) const {
    std::set<ConstraintEvaluationId> found;
    const auto kinds = [family]() -> std::vector<InvalidationKeyKind> {
      switch (family) {
        case EvidenceFamily::Topology: return {InvalidationKeyKind::Topology, InvalidationKeyKind::Node, InvalidationKeyKind::Link, InvalidationKeyKind::LocalityDomain};
        case EvidenceFamily::LinkState: return {InvalidationKeyKind::LinkState};
        case EvidenceFamily::Capability: return {InvalidationKeyKind::Capability};
        case EvidenceFamily::FailureDomain: return {InvalidationKeyKind::FailureDomain, InvalidationKeyKind::IsolationClass};
        case EvidenceFamily::Policy: return {InvalidationKeyKind::Policy};
        case EvidenceFamily::Planner: return {InvalidationKeyKind::Planner};
        case EvidenceFamily::PathAuthority: return {InvalidationKeyKind::PathAuthority};
        default: return {};
      }
    }();
    for (const InvalidationKey& entry : index.keys_of_kinds(kinds)) {
      for (const ConstraintEvaluationId& id : index.dependents(entry)) {
        found.insert(id);
      }
    }
    return std::vector<ConstraintEvaluationId>(found.begin(), found.end());
  }

  [[nodiscard]] std::vector<ConstraintEvaluationId> dependents_of_set(const ConstraintSetId& set_id) const {
    std::set<ConstraintEvaluationId> found;
    for (const ConstraintEvaluationId& id :
         index.dependents(InvalidationKey{InvalidationKeyKind::ConstraintSet, set_id.value()})) {
      found.insert(id);
    }
    for (const EvaluationRecord& record : evaluations) {
      if (record.set_id == set_id) {
        found.insert(record.id);
      }
    }
    return std::vector<ConstraintEvaluationId>(found.begin(), found.end());
  }
};

Coordinator::Coordinator(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Coordinator::~Coordinator() = default;

Result<std::unique_ptr<Coordinator>> Coordinator::open(const CoordinatorConfig& config, Clock* clock) {
  std::string why;
  if (!validate_limits(config.limits, why)) {
    return Result<std::unique_ptr<Coordinator>>::failure(ErrorCode::InvalidArgument, why);
  }
  if (clock == nullptr) {
    return Result<std::unique_ptr<Coordinator>>::failure(ErrorCode::InvalidArgument,
                                                         "a clock is required");
  }
  auto impl = std::make_unique<Impl>();
  impl->config = config;
  impl->clock = clock;
  impl->durable = !config.store_path.empty();
  // The configured evidence generations are the starting authority. Durable
  // state supersedes them below, because a restart must not roll evidence back.
  impl->evidence = config.evidence;

  PersistentState restored;
  bool have_state = false;
  if (impl->durable) {
    auto store = DurableStore::open(config.store_path, config.limits, config.allow_initialize);
    if (!store.ok()) {
      return Result<std::unique_ptr<Coordinator>>::failure(store.code(), store.detail());
    }
    impl->store = std::move(store.value());
    if (impl->store->exists()) {
      auto loaded = impl->store->load();
      if (!loaded.ok()) {
        if (!config.allow_initialize) {
          return Result<std::unique_ptr<Coordinator>>::failure(loaded.code(), loaded.detail());
        }
      } else {
        restored = std::move(loaded.value());
        have_state = true;
      }
    }
  }

  CoordinatorEpoch next_epoch;
  if (have_state && restored.epoch.is_valid()) {
    // Every boot that held live authority in the previous incarnation is fenced
    // for good, together with the boots that were already fenced. A worker from
    // the previous coordinator process can never re-register, even though it
    // can learn the new epoch.
    std::vector<FencedBootRecord> fenced = restored.fenced_boots;
    for (const WorkerBootId& boot : restored.live_boots) {
      bool present = false;
      for (const FencedBootRecord& record : fenced) {
        if (record.boot == boot) {
          present = true;
          break;
        }
      }
      if (!present) {
        FencedBootRecord record;
        record.boot = boot;
        record.fenced_at = restored.epoch;
        record.fenced_tick = impl->now();
        fenced.push_back(record);
      }
    }
    impl->authority.restore_durable_state(restored.epoch, std::move(fenced));
    if (!restored.epoch.next(next_epoch)) {
      return Result<std::unique_ptr<Coordinator>>::failure(ErrorCode::ImpossibleGeneration,
                                                           "coordinator epoch cannot advance without wrapping");
    }
  } else {
    next_epoch = CoordinatorEpoch::from_value(1);
  }
  const Status established = impl->authority.establish_epoch(next_epoch);
  if (!established.ok()) {
    return Result<std::unique_ptr<Coordinator>>::failure(established.code(), established.detail());
  }

  if (have_state) {
    impl->evidence = restored.evidence;
    impl->watermarks = restored.watermarks;
    impl->sets = restored.sets;
    impl->populations = restored.populations;
    impl->last_generation = restored.last_evaluation_generation;
    // Conservative recovery: definitions and candidate populations are
    // restored, but no result is restored as current. Every result must be
    // re-proven against current Path Authority and evidence first.
    impl->evaluations.clear();
    for (EvaluationRecord record : restored.evaluations) {
      record.state = ResultState::RecoveredUnproven;
      impl->evaluations.push_back(std::move(record));
    }
  } else {
    impl->last_generation = EvaluationGeneration::from_value(0);
  }
  impl->rebuild_derived();

  const Status persisted = impl->persist(impl->to_state());
  if (!persisted.ok()) {
    return Result<std::unique_ptr<Coordinator>>::failure(persisted.code(), persisted.detail());
  }
  return Result<std::unique_ptr<Coordinator>>::success(
      std::unique_ptr<Coordinator>(new Coordinator(std::move(impl))));
}

Result<std::unique_ptr<Coordinator>> Coordinator::open_in_memory(const CoordinatorConfig& config,
                                                                 Clock* clock) {
  CoordinatorConfig local = config;
  local.store_path.clear();
  local.allow_initialize = true;
  return open(local, clock);
}

CoordinatorEpoch Coordinator::epoch() const noexcept { return impl_->authority.epoch(); }

const AuthorityRegistry& Coordinator::authority() const noexcept { return impl_->authority; }

const Limits& Coordinator::limits() const noexcept { return impl_->config.limits; }

const EvidenceRequirements& Coordinator::evidence_requirements() const noexcept {
  return impl_->evidence;
}

std::uint64_t Coordinator::now_ticks() const { return impl_->now(); }

std::size_t Coordinator::stored_evaluation_count() const noexcept { return impl_->evaluations.size(); }

const Watermarks& Coordinator::watermarks() const noexcept { return impl_->watermarks; }

const InvalidationIndex& Coordinator::invalidation_index() const noexcept { return impl_->index; }

void Coordinator::set_phase_hook(PhaseHook hook) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->hook = std::move(hook);
}

std::size_t Coordinator::serialized_state_bytes() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  ByteWriter writer;
  encode_persistent_state(writer, impl_->to_state());
  return writer.size();
}

Status Coordinator::flush() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->persist(impl_->to_state());
}

Result<PublisherRegistration> Coordinator::register_publisher(const AuthorityContext& context,
                                                              PublisherId publisher,
                                                              WorkerBootId boot,
                                                              AuthorityScopeMask scopes,
                                                              SessionId session) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!context.epoch.is_valid() || context.epoch != impl_->authority.epoch()) {
    return Result<PublisherRegistration>::failure(
        ErrorCode::EpochMismatch, "registration must carry the current coordinator epoch");
  }
  AuthorityScopeMask granted = 0;
  bool known = false;
  for (const PublisherGrant& grant : impl_->config.grants) {
    if (grant.publisher == publisher) {
      granted = grant.scopes;
      known = true;
      break;
    }
  }
  if (!known) {
    return Result<PublisherRegistration>::failure(
        ErrorCode::Unauthorized,
        "default deny: publisher holds no out-of-band authority grant on this coordinator");
  }
  const AuthorityScopeMask effective = granted & scopes;
  if (effective == 0) {
    return Result<PublisherRegistration>::failure(
        ErrorCode::Unauthorized, "default deny: the requested scopes are not granted");
  }

  PersistentState next = impl_->to_state();
  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.boot = boot;
  registration.session = session;
  registration.scopes = effective;
  registration.registered_tick = impl_->now();
  registration.registered_at = impl_->authority.epoch();
  registration.live = true;

  const Status registered = impl_->authority.register_publisher(registration, impl_->config.limits);
  if (!registered.ok()) {
    return Result<PublisherRegistration>::failure(registered.code(), registered.detail());
  }
  next.epoch = impl_->authority.epoch();
  impl_->refresh_authority_projection(next);
  const Status persisted = impl_->persist(next);
  if (!persisted.ok()) {
    return Result<PublisherRegistration>::failure(persisted.code(), persisted.detail());
  }
  return Result<PublisherRegistration>::success(registration);
}

Status Coordinator::fence_boot(const AuthorityContext& context, WorkerBootId boot) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::AdministerFencing));
  if (!authorized.ok()) {
    return authorized;
  }
  const Result<ReplayVerdict> replay = impl_->authority.observe_attempt(
      context.attempt, Digest256{}, impl_->now(), impl_->config.limits);
  if (!replay.ok()) {
    return Status::failure(replay.code(), replay.detail());
  }
  if (replay.value() == ReplayVerdict::Conflict) {
    return Status::failure(ErrorCode::MutationAttemptConflict,
                           "mutation attempt identity was reused with a different payload");
  }
  if (replay.value() == ReplayVerdict::ExactReplay) {
    return Status::success();
  }
  const Status fenced =
      impl_->authority.fence_boot(boot, impl_->authority.epoch(), impl_->now(), impl_->config.limits);
  if (!fenced.ok()) {
    return fenced;
  }
  PersistentState next = impl_->to_state();
  impl_->refresh_authority_projection(next);
  return impl_->persist(next);
}

Status Coordinator::fence_on_session_loss(SessionId session) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  WorkerBootId boot;
  if (!impl_->authority.boot_of_session(session, boot)) {
    return Status::success();
  }
  const Status fenced =
      impl_->authority.fence_boot(boot, impl_->authority.epoch(), impl_->now(), impl_->config.limits);
  if (!fenced.ok()) {
    return fenced;
  }
  (void)impl_->authority.drop_session(session);
  PersistentState next = impl_->to_state();
  impl_->refresh_authority_projection(next);
  return impl_->persist(next);
}

Status Coordinator::drop_session(const AuthorityContext& context, SessionId session) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::AdministerFencing));
  if (!authorized.ok()) {
    return authorized;
  }
  return impl_->authority.drop_session(session);
}

Result<ReplayVerdict> Coordinator::observe_attempt(const AuthorityContext& context,
                                                   const Digest256& payload) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->authority.observe_attempt(context.attempt, payload, impl_->now(), impl_->config.limits);
}

Result<ConstraintSet> Coordinator::publish_constraint_set(const AuthorityContext& context,
                                                          ConstraintSet set) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::PublishConstraintSet));
  if (!authorized.ok()) {
    return Result<ConstraintSet>::failure(authorized.code(), authorized.detail());
  }
  SemanticHasher hasher;
  hasher.begin("crf.publish.v1");
  hasher.put_u64(set.id.value());
  hasher.put_u32(static_cast<std::uint32_t>(set.constraints.size()));
  for (const Constraint& constraint : set.constraints) {
    feed_digest(hasher, constraint);
  }
  const Result<ReplayVerdict> replay = impl_->authority.observe_attempt(
      context.attempt, hasher.finish(), impl_->now(), impl_->config.limits);
  if (!replay.ok()) {
    return Result<ConstraintSet>::failure(replay.code(), replay.detail());
  }
  if (replay.value() == ReplayVerdict::Conflict) {
    return Result<ConstraintSet>::failure(
        ErrorCode::MutationAttemptConflict,
        "mutation attempt identity was reused with a different payload");
  }
  if (replay.value() == ReplayVerdict::ExactReplay) {
    const ConstraintSet* existing = impl_->find_set(set.id);
    if (existing == nullptr) {
      return Result<ConstraintSet>::failure(ErrorCode::IdempotentReplay,
                                            "exact replay of a publication that is no longer present");
    }
    return Result<ConstraintSet>::success(*existing);
  }

  std::vector<SetDefect> defects;
  std::vector<Contradiction> contradictions;
  ConstraintSet finalized = set;
  finalized.declared_tick = impl_->now();
  const Status valid = validate_and_finalize_constraint_set(finalized, impl_->config.limits, defects,
                                                            contradictions);
  if (!valid.ok()) {
    return Result<ConstraintSet>::failure(valid.code(), valid.detail());
  }

  PersistentState next = impl_->to_state();
  ConstraintSet* existing = nullptr;
  for (ConstraintSet& candidate : next.sets) {
    if (candidate.id == finalized.id) {
      existing = &candidate;
      break;
    }
  }
  if (existing == nullptr) {
    if (next.sets.size() >= impl_->config.limits.max_constraint_sets) {
      return Result<ConstraintSet>::failure(ErrorCode::ResourceLimit,
                                            "constraint set limit reached");
    }
    finalized.generation = ConstraintSetGeneration::from_value(1);
    finalized.state = ConstraintSetState::Declared;
    next.sets.push_back(finalized);
  } else {
    if (existing->digest == finalized.digest) {
      // Semantically identical republication advances nothing.
      finalized.generation = existing->generation;
      finalized.state = existing->state;
    } else {
      ConstraintSetGeneration advanced;
      if (!existing->generation.next(advanced)) {
        return Result<ConstraintSet>::failure(ErrorCode::ImpossibleGeneration,
                                              "constraint set generation cannot advance without wrapping");
      }
      finalized.generation = advanced;
      finalized.state = existing->state;
      if (finalized.state != ConstraintSetState::Active) {
        finalized.state = ConstraintSetState::RevalidationRequired;
      }
    }
    *existing = finalized;
  }

  // The definitions moved: every result that depends on this set must be
  // revalidated. Results of unrelated constraint sets are untouched.
  for (EvaluationRecord& record : next.evaluations) {
    if (record.set_id == finalized.id && record.state == ResultState::Current) {
      record.state = ResultState::RevalidationRequired;
    }
  }

  const Status persisted = impl_->persist(next);
  if (!persisted.ok()) {
    return Result<ConstraintSet>::failure(persisted.code(), persisted.detail());
  }
  impl_->apply_state(next);
  const ConstraintSet* stored = impl_->find_set(finalized.id);
  return Result<ConstraintSet>::success(stored == nullptr ? finalized : *stored);
}

Result<ConstraintSet> Coordinator::apply_lifecycle(const AuthorityContext& context,
                                                   ConstraintSetId set_id, LifecycleEvent event) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::ApplyLifecycle));
  if (!authorized.ok()) {
    return Result<ConstraintSet>::failure(authorized.code(), authorized.detail());
  }
  const Result<ReplayVerdict> replay = impl_->authority.observe_attempt(
      context.attempt,
      digest_of("crf.lifecycle.v1", [&](SemanticHasher& hasher) {
        hasher.put_u64(set_id.value());
        hasher.put_u8(static_cast<std::uint8_t>(event));
      }),
      impl_->now(), impl_->config.limits);
  if (!replay.ok()) {
    return Result<ConstraintSet>::failure(replay.code(), replay.detail());
  }
  if (replay.value() == ReplayVerdict::Conflict) {
    return Result<ConstraintSet>::failure(
        ErrorCode::MutationAttemptConflict,
        "mutation attempt identity was reused with a different payload");
  }

  PersistentState next = impl_->to_state();
  ConstraintSet* target = nullptr;
  for (ConstraintSet& candidate : next.sets) {
    if (candidate.id == set_id) {
      target = &candidate;
      break;
    }
  }
  if (target == nullptr) {
    return Result<ConstraintSet>::failure(ErrorCode::NotFound, "constraint set is not known");
  }
  if (replay.value() == ReplayVerdict::ExactReplay) {
    return Result<ConstraintSet>::success(*target);
  }
  const TransitionOutcome outcome = apply_lifecycle_event(target->state, event);
  if (!outcome.accepted) {
    return Result<ConstraintSet>::failure(ErrorCode::InvalidArgument, outcome.rejection);
  }
  target->state = outcome.next;
  if (target->state != ConstraintSetState::Active) {
    for (EvaluationRecord& record : next.evaluations) {
      if (record.set_id == set_id && record.state == ResultState::Current) {
        record.state = ResultState::RevalidationRequired;
      }
    }
  }
  const Status persisted = impl_->persist(next);
  if (!persisted.ok()) {
    return Result<ConstraintSet>::failure(persisted.code(), persisted.detail());
  }
  impl_->apply_state(next);
  return Result<ConstraintSet>::success(*impl_->find_set(set_id));
}

Result<ConstraintSet> Coordinator::get_constraint_set(ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const ConstraintSet* set = impl_->find_set(set_id);
  if (set == nullptr) {
    return Result<ConstraintSet>::failure(ErrorCode::NotFound, "constraint set is not known");
  }
  return Result<ConstraintSet>::success(*set);
}

std::vector<ConstraintSetId> Coordinator::constraint_set_ids() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<ConstraintSetId> ids;
  ids.reserve(impl_->sets.size());
  for (const ConstraintSet& set : impl_->sets) {
    ids.push_back(set.id);
  }
  return ids;
}

Status Coordinator::set_evidence_requirements(const AuthorityContext& context,
                                              EvidenceRequirements requirements) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->apply_evidence_requirements(context, requirements);
}

Status Coordinator::advance_family(const AuthorityContext& context, EvidenceFamily family,
                                   std::uint64_t generation) {
  if (family == EvidenceFamily::None || family == EvidenceFamily::ConstraintSet) {
    return Status::failure(ErrorCode::InvalidArgument, "family is not an evidence family");
  }
  std::lock_guard<std::mutex> guard(impl_->mutex);
  EvidenceRequirements requirements = impl_->evidence;
  switch (family) {
    case EvidenceFamily::Topology:
      if (!TopologyGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.topology = TopologyGeneration::from_value(generation);
      break;
    case EvidenceFamily::LinkState:
      if (!LinkStateGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.link_state = LinkStateGeneration::from_value(generation);
      break;
    case EvidenceFamily::Capability:
      if (!CapabilityGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.capability = CapabilityGeneration::from_value(generation);
      break;
    case EvidenceFamily::FailureDomain:
      if (!FailureDomainGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.failure_domain = FailureDomainGeneration::from_value(generation);
      break;
    case EvidenceFamily::Policy:
      if (!PolicyGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.policy = PolicyGeneration::from_value(generation);
      break;
    case EvidenceFamily::Planner:
      if (!PlannerGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.planner = PlannerGeneration::from_value(generation);
      break;
    case EvidenceFamily::PathAuthority:
      if (!PathAuthorityGeneration::is_representable(generation)) {
        return Status::failure(ErrorCode::ImpossibleGeneration, "generation is not representable");
      }
      requirements.path_authority = PathAuthorityGeneration::from_value(generation);
      break;
    default:
      return Status::failure(ErrorCode::InvalidArgument, "family is not an evidence family");
  }
  return impl_->apply_evidence_requirements(context, requirements);
}

Status Coordinator::invalidate_key(const AuthorityContext& context, const InvalidationKey& key) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::PublishEvaluation));
  if (!authorized.ok()) {
    return authorized;
  }
  const Result<ReplayVerdict> replay = impl_->authority.observe_attempt(
      context.attempt,
      digest_of("crf.invalidate-key.v1", [&](SemanticHasher& hasher) {
        hasher.put_u8(static_cast<std::uint8_t>(key.kind));
        hasher.put_u64(key.value);
      }),
      impl_->now(), impl_->config.limits);
  if (!replay.ok()) {
    return Status::failure(replay.code(), replay.detail());
  }
  if (replay.value() == ReplayVerdict::Conflict) {
    return Status::failure(ErrorCode::MutationAttemptConflict,
                           "mutation attempt identity was reused with a different payload");
  }
  if (replay.value() == ReplayVerdict::ExactReplay) {
    return Status::success();
  }

  ++impl_->invalidation_sequence;
  if (!impl_->watermarks.advance_key(key, impl_->invalidation_sequence)) {
    return Status::failure(ErrorCode::StaleGeneration, "invalidation watermark never decreases");
  }
  PersistentState next = impl_->to_state();
  next.watermarks = impl_->watermarks;
  const std::vector<ConstraintEvaluationId> dependents = impl_->dependents_of({key});
  const std::set<ConstraintEvaluationId> target(dependents.begin(), dependents.end());
  for (EvaluationRecord& record : next.evaluations) {
    if (target.find(record.id) != target.end() && record.state == ResultState::Current) {
      record.state = ResultState::RevalidationRequired;
    }
  }
  const Status persisted = impl_->persist(next);
  if (!persisted.ok()) {
    return persisted;
  }
  impl_->apply_state(next);
  return Status::success();
}

Result<CommitOutcome> Coordinator::evaluate(const AuthorityContext& context, ConstraintSetId set_id,
                                            std::span<const CandidatePath> candidates,
                                            ConstraintSetGeneration expected_generation) {
  CommitOutcome outcome;
  EvaluationGeneration generation;
  ConstraintSet set_snapshot;
  EvidenceRequirements evidence_snapshot;
  EvidenceFamilyMask mask = 0;
  PhaseHook hook;

  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    const Status authorized =
        impl_->authority.authorize(context, scope_bit(AuthorityScope::PublishEvaluation));
    if (!authorized.ok()) {
      return Result<CommitOutcome>::failure(authorized.code(), authorized.detail());
    }
    const Result<ReplayVerdict> replay = impl_->authority.observe_attempt(
        context.attempt,
        digest_of("crf.evaluate.v1", [&](SemanticHasher& hasher) {
          hasher.put_u64(request_digest(candidates, set_id, expected_generation));
          hasher.put_u64(impl_->evidence.topology.value());
          hasher.put_u64(impl_->evidence.capability.value());
        }),
        impl_->now(), impl_->config.limits);
    if (!replay.ok()) {
      return Result<CommitOutcome>::failure(replay.code(), replay.detail());
    }
    if (replay.value() == ReplayVerdict::Conflict) {
      return Result<CommitOutcome>::failure(
          ErrorCode::MutationAttemptConflict,
          "mutation attempt identity was reused with a different payload");
    }
    if (replay.value() == ReplayVerdict::ExactReplay) {
      outcome.committed = true;
      outcome.rejection_reason = ReasonCode::None;
      outcome.batch.set_id = set_id;
      const ConstraintSet* set = impl_->find_set(set_id);
      if (set != nullptr) {
        outcome.batch.set_generation = set->generation;
      }
      for (const EvaluationRecord& record : impl_->evaluations) {
        if (!(record.set_id == set_id) || record.state != ResultState::Current) {
          continue;
        }
        outcome.batch.records.push_back(record);
      }
      outcome.batch.has_admissible = !outcome.batch.records.empty() &&
                                     std::any_of(outcome.batch.records.begin(),
                                                 outcome.batch.records.end(),
                                                 [](const EvaluationRecord& record) {
                                                   return record.outcome == Outcome::Admissible ||
                                                          record.outcome ==
                                                              Outcome::AdmissibleWithPreferences;
                                                 });
      outcome.batch.batch_outcome = outcome.batch.has_admissible
                                        ? BatchOutcome::AdmissibleCandidatesAvailable
                                        : BatchOutcome::NoAdmissibleCandidate;
      return Result<CommitOutcome>::success(std::move(outcome));
    }

    const ConstraintSet* set = impl_->find_set(set_id);
    if (set == nullptr) {
      return Result<CommitOutcome>::failure(ErrorCode::NotFound, "constraint set is not known");
    }
    if (candidates.size() > impl_->config.limits.max_batch_size) {
      return Result<CommitOutcome>::failure(ErrorCode::ResourceLimit, "batch exceeds the batch limit");
    }
    if (!impl_->last_generation.next(generation)) {
      return Result<CommitOutcome>::failure(ErrorCode::ImpossibleGeneration,
                                            "evaluation generation cannot advance without wrapping");
    }
    impl_->last_generation = generation;
    set_snapshot = *set;
    evidence_snapshot = impl_->evidence;
    mask = consulted_mask(set_snapshot);
    hook = impl_->hook;
  }

  if (hook) {
    hook(CoordinatorPhase::AfterDependencySnapshot);
  }

  EvaluationContext evaluation;
  evaluation.set = &set_snapshot;
  evaluation.current = evidence_snapshot;
  evaluation.requested_set_generation = expected_generation;
  evaluation.limits = &impl_->config.limits;
  evaluation.now_tick = impl_->now();
  evaluation.provenance.epoch = context.epoch;
  evaluation.provenance.publisher = context.publisher;
  evaluation.provenance.worker_boot = context.worker_boot;
  evaluation.provenance.attempt = context.attempt;
  evaluation.provenance.request = context.request;
  evaluation.generation = generation;
  evaluation.authority_verified = true;

  Result<EvaluationBatch> batch = evaluate_batch(evaluation, candidates);
  if (!batch.ok()) {
    return Result<CommitOutcome>::failure(batch.code(), batch.detail());
  }
  outcome.batch = std::move(batch.value());
  outcome.dependency_mask_at_snapshot = mask;

  if (hook) {
    hook(CoordinatorPhase::BeforeCommitVerification);
  }

  bool committed = false;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);

    // Phase three: reacquire and verify that every dependency the evaluation
    // actually used is still exactly what it was when the snapshot was taken.
    ReasonCode stale = ReasonCode::None;
    const ConstraintSet* live = impl_->find_set(set_id);
    if (live == nullptr) {
      outcome.dependency_mask_at_commit = 0;
      stale = ReasonCode::ConstraintSetNotFound;
    } else {
      outcome.dependency_mask_at_commit = consulted_mask(*live);
      if (!(live->generation == set_snapshot.generation) ||
          !(live->digest == set_snapshot.digest) || live->state != set_snapshot.state) {
        stale = ReasonCode::StaleConstraintSetGeneration;
      } else if (!evidence_equal(impl_->evidence, evidence_snapshot)) {
        for (const EvidenceFamily family : kFamilies) {
          if ((mask & family_bit(family)) == 0) {
            continue;
          }
          if (generation_for(impl_->evidence, family) != generation_for(evidence_snapshot, family)) {
            stale = staleness_reason(family);
            break;
          }
        }
        if (stale == ReasonCode::None) {
          stale = ReasonCode::EvidenceNotBound;
        }
      } else {
        for (const EvidenceFamily family : kFamilies) {
          if ((mask & family_bit(family)) == 0) {
            continue;
          }
          if (impl_->watermarks.family(family) > generation_for(evidence_snapshot, family)) {
            stale = staleness_reason(family);
            break;
          }
        }
      }
    }

    if (stale != ReasonCode::None) {
      // A stale completion leaves no authoritative mutation at all.
      for (EvaluationRecord& record : outcome.batch.records) {
        record.state = ResultState::StaleAtCommit;
      }
      outcome.committed = false;
      outcome.rejection_reason = stale;
      return Result<CommitOutcome>::success(std::move(outcome));
    }

    PersistentState next = impl_->to_state();
    // An evaluation identity is derived from the semantic binding, so
    // re-proving the same binding produces the same identity. The previous
    // record for that identity is replaced rather than duplicated: the identity
    // stays stable, and the record holds the newest proven result.
    std::set<ConstraintEvaluationId> committed_ids;
    for (const EvaluationRecord& record : outcome.batch.records) {
      committed_ids.insert(record.id);
    }
    next.evaluations.erase(
        std::remove_if(next.evaluations.begin(), next.evaluations.end(),
                       [&committed_ids](const EvaluationRecord& record) {
                         return committed_ids.find(record.id) != committed_ids.end();
                       }),
        next.evaluations.end());
    for (EvaluationRecord& record : next.evaluations) {
      if (record.set_id == set_id && record.state != ResultState::StaleAtCommit) {
        record.state = ResultState::Superseded;
      }
    }
    for (EvaluationRecord& record : outcome.batch.records) {
      record.state = ResultState::Current;
      record.committed_tick = evaluation.now_tick;
      next.evaluations.push_back(record);
    }
    bool population_replaced = false;
    std::vector<CandidatePath> stored(candidates.begin(), candidates.end());
    std::stable_sort(stored.begin(), stored.end(), candidate_canonical_less);
    for (CandidatePopulation& population : next.populations) {
      if (population.set_id == set_id) {
        population.candidates = stored;
        population_replaced = true;
        break;
      }
    }
    if (!population_replaced) {
      if (next.populations.size() >= impl_->config.max_candidate_populations) {
        next.populations.erase(next.populations.begin());
      }
      CandidatePopulation population;
      population.set_id = set_id;
      population.candidates = std::move(stored);
      next.populations.push_back(std::move(population));
    }
    next.last_evaluation_generation = generation;

    // Bounded history: the oldest non-current record is evicted first.
    const std::size_t history_limit = impl_->config.limits.max_evaluations_retained;
    while (next.evaluations.size() > history_limit) {
      std::size_t victim = next.evaluations.size();
      EvaluationGeneration oldest;
      for (std::size_t index = 0; index < next.evaluations.size(); ++index) {
        if (next.evaluations[index].state == ResultState::Current) {
          continue;
        }
        if (victim == next.evaluations.size() || next.evaluations[index].generation < oldest) {
          victim = index;
          oldest = next.evaluations[index].generation;
        }
      }
      if (victim == next.evaluations.size()) {
        break;
      }
      next.evaluations.erase(next.evaluations.begin() + static_cast<std::ptrdiff_t>(victim));
    }

    const Status persisted = impl_->persist(next);
    if (!persisted.ok()) {
      outcome.committed = false;
      outcome.rejection_reason = ReasonCode::MalformedFrame;
      for (EvaluationRecord& record : outcome.batch.records) {
        record.state = ResultState::StaleAtCommit;
      }
      return Result<CommitOutcome>::failure(persisted.code(), persisted.detail());
    }
    impl_->apply_state(next);
    outcome.committed = true;
    committed = true;
  }

  if (committed && hook) {
    hook(CoordinatorPhase::AfterCommit);
  }
  return Result<CommitOutcome>::success(std::move(outcome));
}

Result<CommitOutcome> Coordinator::revalidate(const AuthorityContext& context,
                                              ConstraintSetId set_id) {
  std::vector<CandidatePath> population;
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (const CandidatePopulation& entry : impl_->populations) {
      if (entry.set_id == set_id) {
        population = entry.candidates;
        break;
      }
    }
  }
  if (population.empty()) {
    return Result<CommitOutcome>::failure(ErrorCode::NotFound,
                                          "no retained candidate population for this constraint set");
  }
  return evaluate(context, set_id, population, ConstraintSetGeneration{});
}

Result<std::vector<RouteFabricHandoff>> Coordinator::handoffs(const AuthorityContext& context,
                                                              ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Status authorized =
      impl_->authority.authorize(context, scope_bit(AuthorityScope::ReadResults));
  if (!authorized.ok()) {
    return Result<std::vector<RouteFabricHandoff>>::failure(authorized.code(), authorized.detail());
  }
  std::vector<RouteFabricHandoff> result;
  for (const EvaluationRecord& record : impl_->evaluations) {
    if (!(record.set_id == set_id) || record.state != ResultState::Current) {
      continue;
    }
    result.push_back(handoff_of(record));
  }
  std::sort(result.begin(), result.end(),
            [](const RouteFabricHandoff& a, const RouteFabricHandoff& b) { return a.path < b.path; });
  return Result<std::vector<RouteFabricHandoff>>::success(std::move(result));
}

Result<EvaluationRecord> Coordinator::current_result(ConstraintSetId set_id, PathId path) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->current.find(std::make_pair(set_id.value(), path.value()));
  if (found == impl_->current.end()) {
    return Result<EvaluationRecord>::failure(ErrorCode::NotFound, "no current result for this path");
  }
  for (const EvaluationRecord& record : impl_->evaluations) {
    if (record.id == found->second) {
      return Result<EvaluationRecord>::success(record);
    }
  }
  return Result<EvaluationRecord>::failure(ErrorCode::NotFound, "current result index is inconsistent");
}

Result<CurrentnessReport> Coordinator::currentness(ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const ConstraintSet* set = impl_->find_set(set_id);
  if (set == nullptr) {
    return Result<CurrentnessReport>::failure(ErrorCode::NotFound, "constraint set is not known");
  }
  CurrentnessReport report;
  report.set_id = set_id;
  report.set_generation = set->generation;
  report.state = set->state;
  report.evaluation_generation = impl_->last_generation;
  report.required_evidence = impl_->evidence;
  report.published_evidence = set->evidence;
  report.publisher_authority_live = impl_->authority.live_publishers() != 0;

  std::set<CurrentnessCause> causes;
  if (set->state != ConstraintSetState::Active) {
    causes.insert(CurrentnessCause::ConstraintSetStateChanged);
  }
  if (!evidence_equal(set->evidence, impl_->evidence)) {
    causes.insert(CurrentnessCause::EvidenceRequirementChanged);
  }
  bool any_current = false;
  for (const EvaluationRecord& record : impl_->evaluations) {
    if (!(record.set_id == set_id)) {
      continue;
    }
    switch (record.state) {
      case ResultState::Current: any_current = true; ++report.current_results; break;
      case ResultState::RevalidationRequired:
        ++report.revalidation_required;
        causes.insert(CurrentnessCause::DependencyInvalidated);
        break;
      case ResultState::RecoveredUnproven:
        ++report.recovered_unproven;
        causes.insert(CurrentnessCause::RecoveredUnproven);
        break;
      case ResultState::Superseded: break;
      case ResultState::StaleAtCommit: break;
    }
  }
  if (!any_current) {
    causes.insert(CurrentnessCause::NoCurrentResult);
  }
  for (const EvidenceFamily family : kFamilies) {
    if (impl_->watermarks.family(family) > generation_for(impl_->evidence, family)) {
      switch (family) {
        case EvidenceFamily::PathAuthority: causes.insert(CurrentnessCause::PathAuthorityAdvanced); break;
        case EvidenceFamily::Topology: causes.insert(CurrentnessCause::TopologyAdvanced); break;
        case EvidenceFamily::LinkState: causes.insert(CurrentnessCause::LinkStateAdvanced); break;
        case EvidenceFamily::Capability: causes.insert(CurrentnessCause::CapabilityAdvanced); break;
        case EvidenceFamily::FailureDomain:
          causes.insert(CurrentnessCause::FailureDomainAdvanced);
          break;
        case EvidenceFamily::Policy: causes.insert(CurrentnessCause::PolicyAdvanced); break;
        case EvidenceFamily::Planner: causes.insert(CurrentnessCause::PlannerAdvanced); break;
        default: break;
      }
    }
  }
  report.causes.assign(causes.begin(), causes.end());
  std::sort(report.causes.begin(), report.causes.end());
  return Result<CurrentnessReport>::success(std::move(report));
}

Result<DefinitionsSnapshot> Coordinator::snapshot_definitions(ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const ConstraintSet* set = impl_->find_set(set_id);
  if (set == nullptr) {
    return Result<DefinitionsSnapshot>::failure(ErrorCode::NotFound, "constraint set is not known");
  }
  return Result<DefinitionsSnapshot>::success(crf::snapshot_definitions(*set));
}

Result<ResultsSnapshot> Coordinator::snapshot_results(ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const ConstraintSet* set = impl_->find_set(set_id);
  if (set == nullptr) {
    return Result<ResultsSnapshot>::failure(ErrorCode::NotFound, "constraint set is not known");
  }
  std::vector<CandidateResultView> views;
  for (const EvaluationRecord& record : impl_->evaluations) {
    if (!(record.set_id == set_id)) {
      continue;
    }
    CandidateResultView view;
    view.path = record.path;
    view.authority_generation = record.authority_generation;
    view.outcome = record.outcome;
    view.primary_reason = record.primary_reason;
    view.state = record.state;
    view.evaluation_id = record.id;
    view.evaluation_generation = record.generation;
    view.digest = record.digest;
    views.push_back(view);
  }
  return Result<ResultsSnapshot>::success(
      crf::snapshot_results(set_id, set->generation, impl_->last_generation, std::move(views)));
}

Result<std::vector<CandidatePath>> Coordinator::retained_candidates(ConstraintSetId set_id) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  for (const CandidatePopulation& entry : impl_->populations) {
    if (entry.set_id == set_id) {
      return Result<std::vector<CandidatePath>>::success(entry.candidates);
    }
  }
  return Result<std::vector<CandidatePath>>::failure(ErrorCode::NotFound,
                                                     "no retained candidate population");
}

}  // namespace crf
