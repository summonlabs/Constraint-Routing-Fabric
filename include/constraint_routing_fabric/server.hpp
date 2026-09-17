// Constraint Routing Fabric -- coordinator server over the loopback transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_SERVER_HPP
#define CONSTRAINT_ROUTING_FABRIC_SERVER_HPP

#include <cstdint>
#include <memory>

#include "constraint_routing_fabric/coordinator.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

struct ServerConfig {
  Limits limits{};
  /// Zero selects an ephemeral loopback port.
  std::uint16_t port{0};
};

/// Serves the coordinator protocol. The transport is unauthenticated loopback:
/// authorization comes entirely from the coordinator's out-of-band grant list,
/// never from the fact that a peer connected.
class CoordinatorServer {
 public:
  CoordinatorServer(const CoordinatorServer&) = delete;
  CoordinatorServer& operator=(const CoordinatorServer&) = delete;
  ~CoordinatorServer();

  [[nodiscard]] static Result<std::unique_ptr<CoordinatorServer>> start(Coordinator& coordinator,
                                                                        const ServerConfig& config);

  /// Accepts and serves connections until ::stop is requested.
  [[nodiscard]] Status run();
  [[nodiscard]] Status stop();

  [[nodiscard]] std::uint16_t port() const noexcept;
  [[nodiscard]] std::size_t sessions_accepted() const noexcept;
  [[nodiscard]] std::size_t frames_handled() const noexcept;
  [[nodiscard]] std::size_t active_sessions() const noexcept;

 private:
  class Impl;
  explicit CoordinatorServer(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_{};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_SERVER_HPP
