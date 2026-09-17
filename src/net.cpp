// Constraint Routing Fabric -- minimal loopback transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/net.hpp"

#include <atomic>
#include <cstring>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// The Windows SDK socket headers are third-party code: their static-analysis
// findings are not first-party findings and are not actionable here.
#pragma warning(push)
#pragma warning(disable : 6101 6387 6001 6011)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace crf {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
constexpr native_socket kInvalidSocket = INVALID_SOCKET;
[[nodiscard]] int last_error() noexcept { return WSAGetLastError(); }
void close_socket(native_socket socket) noexcept {
  if (socket != kInvalidSocket) {
    ::closesocket(socket);
  }
}
#else
using native_socket = int;
constexpr native_socket kInvalidSocket = -1;
[[nodiscard]] int last_error() noexcept { return errno; }
void close_socket(native_socket socket) noexcept {
  if (socket != kInvalidSocket) {
    ::close(socket);
  }
}
#endif

std::atomic<int> g_runtime_users{0};
std::atomic<bool> g_runtime_ready{false};

}  // namespace

struct TcpSocket::Impl {
  native_socket handle{kInvalidSocket};
};

SocketRuntime::SocketRuntime() { (void)initialize(); }

SocketRuntime::~SocketRuntime() {
  if (g_runtime_users.fetch_sub(1) == 1) {
    g_runtime_ready.store(false);
  }
}

Status SocketRuntime::initialize() {
  if (g_runtime_ready.load()) {
    g_runtime_users.fetch_add(1);
    return Status::success();
  }
#if defined(_WIN32)
  WSADATA data{};
  const int result = WSAStartup(MAKEWORD(2, 2), &data);
  if (result != 0) {
    return Status::failure(ErrorCode::TransportFailure, "Winsock initialization failed");
  }
#endif
  g_runtime_ready.store(true);
  g_runtime_users.fetch_add(1);
  return Status::success();
}

bool SocketRuntime::initialized() noexcept { return g_runtime_ready.load(); }

TcpSocket::TcpSocket() = default;

TcpSocket::TcpSocket(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : impl_(std::move(other.impl_)) {}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    (void)close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

TcpSocket::~TcpSocket() { (void)close(); }

bool TcpSocket::valid() const noexcept {
  return impl_ != nullptr && impl_->handle != kInvalidSocket;
}

Status TcpSocket::connect_loopback(std::uint16_t port) {
  if (!SocketRuntime::initialized()) {
    const Status started = SocketRuntime::initialize();
    if (!started.ok()) {
      return started;
    }
  }
  auto impl = std::make_unique<Impl>();
  impl->handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (impl->handle == kInvalidSocket) {
    return Status::failure(ErrorCode::TransportFailure, "cannot create a loopback socket");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(impl->handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(impl->handle);
    return Status::failure(ErrorCode::TransportFailure,
                           std::string("cannot connect to loopback port; socket error ") +
                               std::to_string(last_error()));
  }
  impl_ = std::move(impl);
  return set_no_delay();
}

Status TcpSocket::set_no_delay() {
  if (!valid()) {
    return Status::failure(ErrorCode::TransportFailure, "socket is not open");
  }
  int enabled = 1;
  (void)::setsockopt(impl_->handle, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&enabled), sizeof(enabled));
  return Status::success();
}

Status TcpSocket::send_all(std::span<const std::byte> data) {
  if (!valid()) {
    return Status::failure(ErrorCode::TransportFailure, "socket is not open");
  }
  std::size_t sent = 0;
  while (sent < data.size()) {
    const int chunk = static_cast<int>(
        (data.size() - sent) > 0x40000000u ? 0x40000000u : (data.size() - sent));
    const int produced = ::send(impl_->handle, reinterpret_cast<const char*>(data.data() + sent), chunk, 0);
    if (produced <= 0) {
      return Status::failure(ErrorCode::TransportFailure,
                             std::string("send failed; socket error ") + std::to_string(last_error()));
    }
    sent += static_cast<std::size_t>(produced);
  }
  return Status::success();
}

Status TcpSocket::recv_some(std::span<std::byte> data, std::size_t& received) {
  received = 0;
  if (!valid()) {
    return Status::failure(ErrorCode::TransportFailure, "socket is not open");
  }
  if (data.empty()) {
    return Status::success();
  }
  const int chunk = static_cast<int>(data.size() > 0x40000000u ? 0x40000000u : data.size());
  const int produced = ::recv(impl_->handle, reinterpret_cast<char*>(data.data()), chunk, 0);
  if (produced < 0) {
    return Status::failure(ErrorCode::TransportFailure,
                           std::string("receive failed; socket error ") + std::to_string(last_error()));
  }
  received = static_cast<std::size_t>(produced);
  return Status::success();
}

Status TcpSocket::close() {
  if (impl_ != nullptr) {
    close_socket(impl_->handle);
    impl_->handle = kInvalidSocket;
    impl_.reset();
  }
  return Status::success();
}

void TcpSocket::abort() {
  if (valid()) {
#if defined(_WIN32)
    (void)::shutdown(impl_->handle, SD_BOTH);
#else
    (void)::shutdown(impl_->handle, SHUT_RDWR);
#endif
  }
}

void TcpSocket::shutdown_send() {
  if (valid()) {
#if defined(_WIN32)
    (void)::shutdown(impl_->handle, SD_SEND);
#else
    (void)::shutdown(impl_->handle, SHUT_WR);
#endif
  }
}

TcpListener::~TcpListener() { (void)close(); }

bool TcpListener::valid() const noexcept {
  return handle_ != ~std::uintptr_t{0};
}

Status TcpListener::bind_loopback(std::uint16_t port) {
  if (!SocketRuntime::initialized()) {
    const Status started = SocketRuntime::initialize();
    if (!started.ok()) {
      return started;
    }
  }
  (void)close();
  const native_socket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    return Status::failure(ErrorCode::TransportFailure, "cannot create a listener socket");
  }
  int enabled = 1;
  (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&enabled),
                     sizeof(enabled));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_socket(handle);
    return Status::failure(ErrorCode::TransportFailure,
                           std::string("cannot bind loopback port; socket error ") +
                               std::to_string(last_error()));
  }
  if (::listen(handle, 16) != 0) {
    close_socket(handle);
    return Status::failure(ErrorCode::TransportFailure, "cannot listen on the loopback port");
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int bound_length = static_cast<int>(sizeof(bound));
#else
  socklen_t bound_length = static_cast<socklen_t>(sizeof(bound));
#endif
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
    port_ = ntohs(bound.sin_port);
  } else {
    port_ = port;
  }
  handle_ = static_cast<std::uintptr_t>(handle);
  return Status::success();
}

Status TcpListener::accept(TcpSocket& out) {
  if (!valid()) {
    return Status::failure(ErrorCode::TransportFailure, "listener is not open");
  }
  const native_socket handle = static_cast<native_socket>(handle_);
  const native_socket accepted = ::accept(handle, nullptr, nullptr);
  if (accepted == kInvalidSocket) {
    return Status::failure(ErrorCode::TransportFailure,
                           std::string("accept failed; socket error ") + std::to_string(last_error()));
  }
  auto impl = std::make_unique<TcpSocket::Impl>();
  impl->handle = accepted;
  out = TcpSocket(std::move(impl));
  return out.set_no_delay();
}

Status TcpListener::close() {
  if (valid()) {
    close_socket(static_cast<native_socket>(handle_));
    handle_ = ~std::uintptr_t{0};
  }
  return Status::success();
}

}  // namespace crf
