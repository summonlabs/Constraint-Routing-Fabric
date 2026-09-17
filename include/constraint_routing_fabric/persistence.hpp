// Constraint Routing Fabric -- versioned durable state with integrity checking.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_PERSISTENCE_HPP
#define CONSTRAINT_ROUTING_FABRIC_PERSISTENCE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/invalidation.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// The candidate population a constraint set was last evaluated against.
/// Retained so that a set can be revalidated after an invalidation or a
/// restart without asking the planner again.
struct CandidatePopulation {
  ConstraintSetId set_id{};
  std::vector<CandidatePath> candidates{};
};

/// Everything the coordinator keeps durably. Live publisher authority is never
/// part of it: durable state is not live authority.
struct PersistentState {
  CoordinatorEpoch epoch{};
  EvidenceRequirements evidence{};
  Watermarks watermarks{};
  std::vector<ConstraintSet> sets{};
  std::vector<EvaluationRecord> evaluations{};
  std::vector<CandidatePopulation> populations{};
  /// Worker boots that held live authority in the recorded coordinator epoch.
  /// A restart fences all of them: a worker from a previous coordinator
  /// incarnation can never re-register, even though it knows the new epoch.
  std::vector<WorkerBootId> live_boots{};
  std::vector<FencedBootRecord> fenced_boots{};
  std::vector<MutationAttemptRecord> attempts{};
  EvaluationGeneration last_evaluation_generation{};
  bool initialized{false};
};

/// Envelope: magic, format version, payload length, payload, CRC-32C and
/// SHA-256 over the payload. Deterministic: the same state always produces the
/// same bytes.
[[nodiscard]] std::vector<std::byte> encode_envelope(std::span<const std::byte> payload);
[[nodiscard]] Status decode_envelope(std::span<const std::byte> raw, const Limits& limits,
                                     std::vector<std::byte>& payload);

void encode_persistent_state(ByteWriter& writer, const PersistentState& state);
[[nodiscard]] bool decode_persistent_state(ByteReader& reader, const Limits& limits,
                                           PersistentState& out);

/// Full semantic validation. Rejects duplicate constraint ids, dangling
/// evidence bindings, unknown constraint kinds, invalid numeric bounds,
/// impossible generations, contradictory normalized representations, duplicate
/// evaluation identities, malformed reason vectors, absurd counts, overflow and
/// trailing bytes.
[[nodiscard]] Status validate_persistent_state(const PersistentState& state, const Limits& limits);

[[nodiscard]] Digest256 persistent_state_digest(const PersistentState& state);

/// Durable store with atomic replacement and a durability barrier: ::save only
/// reports success after the bytes are on stable storage. A caller that
/// requires durability must not acknowledge before ::save returns ok.
class DurableStore {
 public:
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  ~DurableStore();

  /// Opens (or creates) the store. When the file exists but fails validation
  /// the open fails unless \p allow_initialize is set, in which case the
  /// unreadable file is preserved as a quarantine copy and a fresh store is
  /// created. Recovery never silently discards evidence.
  [[nodiscard]] static Result<std::unique_ptr<DurableStore>> open(const std::string& path,
                                                                 const Limits& limits,
                                                                 bool allow_initialize);

  [[nodiscard]] Status save(const PersistentState& state);
  [[nodiscard]] Result<PersistentState> load() const;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] bool exists() const;
  [[nodiscard]] std::uint64_t successful_writes() const noexcept { return writes_; }
  [[nodiscard]] std::uint64_t failed_writes() const noexcept { return failures_; }
  [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

 private:
  DurableStore(std::string path, Limits limits);

  std::string path_{};
  Limits limits_{};
  std::uint64_t writes_{0};
  std::uint64_t failures_{0};
  /// Exclusive ownership handle for the store path. A second coordinator on the
  /// same store would be able to roll the durable epoch backwards, so the store
  /// is owned by exactly one open instance at a time. The handle is released by
  /// the operating system if the owning process dies, so a hard kill never
  /// leaves a store permanently locked.
  std::uintptr_t lock_handle_{~std::uintptr_t{0}};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_PERSISTENCE_HPP
