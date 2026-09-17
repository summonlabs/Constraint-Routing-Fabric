// Constraint Routing Fabric -- minimal loopback transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_NET_HPP
#define CONSTRAINT_ROUTING_FABRIC_NET_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Process-wide socket runtime. Construction is idempotent per process.
class SocketRuntime {
 public:
  SocketRuntime();
  SocketRuntime(const SocketRuntime&) = delete;
  SocketRuntime& operator=(const SocketRuntime&) = delete;
  ~SocketRuntime();

  [[nodiscard]] static Status initialize();
  [[nodiscard]] static bool initialized() noexcept;
};

/// Blocking TCP socket. Transport only: it makes no claim about authentication
/// or confidentiality, and no cryptographic property is provided.
class TcpSocket {
 public:
  TcpSocket();
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;
  TcpSocket(TcpSocket&& other) noexcept;
  TcpSocket& operator=(TcpSocket&& other) noexcept;
  ~TcpSocket();

  [[nodiscard]] Status connect_loopback(std::uint16_t port);
  [[nodiscard]] Status send_all(std::span<const std::byte> data);
  /// Receives up to data.size() bytes. Sets received to zero on orderly close.
  [[nodiscard]] Status recv_some(std::span<std::byte> data, std::size_t& received);
  [[nodiscard]] Status close();
  [[nodiscard]] bool valid() const noexcept;
  void shutdown_send();
  /// Aborts both directions so a blocking receive on another thread returns.
  void abort();

  /// Disables Nagle so a small control frame is not delayed.
  [[nodiscard]] Status set_no_delay();

 private:
  friend class TcpListener;
  struct Impl;
  explicit TcpSocket(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_{};
};

/// Loopback listener used by the coordinator.
class TcpListener {
 public:
  TcpListener() = default;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;
  ~TcpListener();

  /// Binds 127.0.0.1 on \p port. Port zero selects an ephemeral port.
  [[nodiscard]] Status bind_loopback(std::uint16_t port);
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] Status accept(TcpSocket& out);
  [[nodiscard]] Status close();

 private:
  std::uintptr_t handle_{~std::uintptr_t{0}};
  std::uint16_t port_{0};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_NET_HPP
