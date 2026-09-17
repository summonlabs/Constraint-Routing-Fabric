// Constraint Routing Fabric -- distributed authority, epochs and fencing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Default deny. Being connected is not being authorized. Being a known
// publisher is not being authorized. Durable state is not live authority.
#ifndef CONSTRAINT_ROUTING_FABRIC_AUTHORITY_HPP
#define CONSTRAINT_ROUTING_FABRIC_AUTHORITY_HPP

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Scopes a publisher may hold. Default deny: an empty mask authorizes nothing.
enum class AuthorityScope : std::uint32_t {
  None = 0,
  PublishConstraintSet = 1u << 0,
  PublishEvaluation = 1u << 1,
  ApplyLifecycle = 1u << 2,
  ReadDefinitions = 1u << 3,
  ReadResults = 1u << 4,
  RegisterPublisher = 1u << 5,
  AdministerFencing = 1u << 6,
};

using AuthorityScopeMask = std::uint32_t;

[[nodiscard]] constexpr AuthorityScopeMask scope_bit(AuthorityScope scope) noexcept {
  return static_cast<AuthorityScopeMask>(scope);
}
[[nodiscard]] constexpr bool has_scope(AuthorityScopeMask mask, AuthorityScope scope) noexcept {
  return (mask & scope_bit(scope)) != 0;
}
[[nodiscard]] const char* to_string(AuthorityScope scope) noexcept;

/// Every mutating operation carries this context. Without it the operation is
/// rejected before any semantic work happens.
struct AuthorityContext {
  CoordinatorEpoch epoch{};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  MutationAttemptId attempt{};
  RequestId request{};
  SessionId session{};
  AuthorityScopeMask scopes{0};
};

/// Verdict of the mutation-attempt de-duplication.
enum class ReplayVerdict : std::uint8_t {
  Fresh = 1,
  ExactReplay = 2,
  Conflict = 3,
};

struct MutationAttemptRecord {
  MutationAttemptId attempt{};
  Digest256 payload{};
  std::uint64_t recorded_tick{0};
};

struct FencedBootRecord {
  WorkerBootId boot{};
  CoordinatorEpoch fenced_at{};
  std::uint64_t fenced_tick{0};
};

struct PublisherRegistration {
  PublisherId publisher{};
  WorkerBootId boot{};
  SessionId session{};
  AuthorityScopeMask scopes{0};
  std::uint64_t registered_tick{0};
  CoordinatorEpoch registered_at{};
  bool live{false};
};

/// Live authority registry. Nothing here is durable: after a restart no live
/// publisher authority is restored, and every previously known boot is fenced.
class AuthorityRegistry {
 public:
  AuthorityRegistry() = default;

  /// Establishes the coordinator epoch. Epochs are strictly monotonic; a lower
  /// or equal epoch is refused.
  [[nodiscard]] Status establish_epoch(CoordinatorEpoch epoch);
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept { return epoch_; }

  /// Registers a publisher for the current epoch. A fenced boot can never
  /// register again, in this or any later epoch.
  [[nodiscard]] Status register_publisher(const PublisherRegistration& registration, const Limits& limits);

  /// Removes live authority for one session without fencing the boot.
  [[nodiscard]] Status drop_session(SessionId session);
  /// Returns the boot that owns a live session, if any.
  [[nodiscard]] bool boot_of_session(SessionId session, WorkerBootId& out) const noexcept;

  /// Permanently fences a worker boot. Idempotent.
  [[nodiscard]] Status fence_boot(WorkerBootId boot, CoordinatorEpoch at, std::uint64_t tick,
                                  const Limits& limits);
  [[nodiscard]] bool is_boot_fenced(WorkerBootId boot) const noexcept;
  [[nodiscard]] std::size_t live_publishers() const noexcept;
  [[nodiscard]] std::size_t live_sessions() const noexcept;
  [[nodiscard]] std::size_t fenced_boots() const noexcept { return fenced_.size(); }

  /// Full authorization check for a mutating operation: epoch, live session,
  /// registered publisher, exact boot match, not fenced, and scope held.
  [[nodiscard]] Status authorize(const AuthorityContext& context, AuthorityScopeMask required) const;

  /// Mutation-attempt de-duplication. An exact replay is idempotent and
  /// advances nothing. Reuse with a different payload is a conflict.
  [[nodiscard]] Result<ReplayVerdict> observe_attempt(MutationAttemptId attempt, const Digest256& payload,
                                                      std::uint64_t tick, const Limits& limits);

  [[nodiscard]] const std::map<WorkerBootId, FencedBootRecord>& fenced() const noexcept { return fenced_; }
  [[nodiscard]] const std::vector<PublisherRegistration>& registrations() const noexcept {
    return registrations_;
  }
  [[nodiscard]] const std::vector<MutationAttemptRecord>& attempts() const noexcept { return attempts_; }

  /// Restores the durable part of authority state: the epoch and the fenced
  /// boot set. No live publisher authority is restored.
  void restore_durable_state(CoordinatorEpoch epoch, std::vector<FencedBootRecord> fenced);

  /// Generates a fresh, never-reused worker boot identity for this process.
  [[nodiscard]] static WorkerBootId fresh_worker_boot() noexcept;

  void clear_live_authority() noexcept;

 private:
  CoordinatorEpoch epoch_{};
  std::map<WorkerBootId, FencedBootRecord> fenced_{};
  std::vector<PublisherRegistration> registrations_{};
  std::vector<MutationAttemptRecord> attempts_{};
};

void encode_fenced_boot(ByteWriter& writer, const FencedBootRecord& record);
[[nodiscard]] bool decode_fenced_boot(ByteReader& reader, FencedBootRecord& out);
void encode_mutation_attempt(ByteWriter& writer, const MutationAttemptRecord& record);
[[nodiscard]] bool decode_mutation_attempt(ByteReader& reader, MutationAttemptRecord& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_AUTHORITY_HPP
