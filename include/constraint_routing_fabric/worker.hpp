// Constraint Routing Fabric -- distributed worker client.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_WORKER_HPP
#define CONSTRAINT_ROUTING_FABRIC_WORKER_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/coordinator.hpp"
#include "constraint_routing_fabric/net.hpp"
#include "constraint_routing_fabric/protocol.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

struct WorkerConfig {
  std::uint16_t port{0};
  PublisherId publisher{};
  AuthorityScopeMask requested_scopes{0};
  std::string client_name{};
  /// Worker boot identity. Zero generates a fresh identity for this process,
  /// which is the normal case. A caller may declare a specific identity only to
  /// prove that the coordinator refuses a fenced one: the coordinator is the
  /// authority on fencing, never the client.
  WorkerBootId boot{};
};

/// A publisher process. Every process instantiates a fresh ::WorkerBootId; an
/// old boot stays permanently fenced and can never publish again.
class WorkerClient {
 public:
  WorkerClient(const WorkerClient&) = delete;
  WorkerClient& operator=(const WorkerClient&) = delete;
  ~WorkerClient();

  [[nodiscard]] static Result<std::unique_ptr<WorkerClient>> connect(const WorkerConfig& config,
                                                                     const Limits& limits);

  [[nodiscard]] Result<ConstraintSet> publish_constraint_set(const ConstraintSet& set);
  [[nodiscard]] Result<ConstraintSet> apply_lifecycle(ConstraintSetId set_id, LifecycleEvent event);
  [[nodiscard]] Result<CommitOutcome> evaluate(ConstraintSetId set_id,
                                               std::span<const CandidatePath> candidates);
  [[nodiscard]] Result<DefinitionsSnapshot> query_definitions(ConstraintSetId set_id);
  [[nodiscard]] Result<ResultsSnapshot> query_results(ConstraintSetId set_id);
  [[nodiscard]] Result<CurrentnessReport> query_currentness(ConstraintSetId set_id);
  [[nodiscard]] Status heartbeat();

  [[nodiscard]] WorkerBootId boot() const noexcept { return boot_; }
  [[nodiscard]] SessionId session() const noexcept { return session_; }
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] AuthorityScopeMask granted_scopes() const noexcept { return granted_scopes_; }
  [[nodiscard]] Status close();

  /// Builds the authority context for the next mutation. The attempt id is
  /// drawn from a process-local monotonic counter.
  [[nodiscard]] AuthorityContext next_context();

 private:
  WorkerClient();
  [[nodiscard]] Result<Frame> round_trip(MessageId request, const std::vector<std::byte>& payload);

  TcpSocket socket_{};
  Limits limits_{};
  WorkerBootId boot_{};
  SessionId session_{};
  CoordinatorEpoch epoch_{};
  AuthorityScopeMask granted_scopes_{0};
  PublisherId publisher_{};
  std::uint64_t attempt_counter_{0};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_WORKER_HPP
