// Constraint Routing Fabric -- coordinator server implementation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/server.hpp"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "constraint_routing_fabric/messages.hpp"
#include "constraint_routing_fabric/net.hpp"
#include "constraint_routing_fabric/protocol.hpp"

namespace crf {
namespace {

struct SessionState {
  SessionId session{};
  PublisherId publisher{};
  WorkerBootId boot{};
  AuthorityScopeMask scopes{0};
  bool registered{false};
};

}  // namespace

class CoordinatorServer::Impl {
 public:
  Coordinator* coordinator{nullptr};
  ServerConfig config{};
  TcpListener listener{};
  std::atomic<bool> stopping{false};
  std::atomic<std::uint64_t> next_session{0};
  std::atomic<std::size_t> sessions_accepted{0};
  std::atomic<std::size_t> frames_handled{0};
  std::mutex mutex{};
  std::map<std::uint64_t, std::shared_ptr<TcpSocket>> sessions{};
  std::vector<std::thread> threads{};

  [[nodiscard]] std::size_t active_session_count() {
    std::lock_guard<std::mutex> guard(mutex);
    return sessions.size();
  }

  [[nodiscard]] Status send_frame(TcpSocket& socket, MessageId message, const SessionState& state,
                                  const FrameHeader& request, const std::vector<std::byte>& payload) {
    Frame frame;
    frame.header.message = message;
    frame.header.epoch = coordinator->epoch();
    frame.header.publisher = state.publisher;
    frame.header.worker_boot = state.boot;
    frame.header.attempt = request.attempt;
    frame.header.request = request.request;
    frame.header.scopes = state.scopes;
    frame.payload = payload;
    std::vector<std::byte> encoded;
    const Status status = encode_frame(frame, config.limits, encoded);
    if (!status.ok()) {
      return status;
    }
    return socket.send_all(encoded);
  }

  [[nodiscard]] Status send_error(TcpSocket& socket, const SessionState& state,
                                  const FrameHeader& request, ErrorCode code, ReasonCode reason,
                                  const std::string& detail) {
    ErrorReportPayload payload;
    payload.code = code;
    payload.reason = reason;
    payload.detail = detail.size() > config.limits.max_detail_bytes
                         ? detail.substr(0, config.limits.max_detail_bytes)
                         : detail;
    ByteWriter writer;
    encode_error_report(writer, payload);
    return send_frame(socket, MessageId::ErrorReport, state, request, writer.buffer());
  }

  [[nodiscard]] AuthorityContext context_for(const SessionState& state,
                                             const FrameHeader& header) const {
    AuthorityContext context;
    context.epoch = coordinator->epoch();
    context.publisher = state.publisher;
    context.worker_boot = state.boot;
    context.attempt = header.attempt;
    context.request = header.request;
    context.session = state.session;
    context.scopes = state.scopes;
    return context;
  }

  [[nodiscard]] bool identity_matches(const SessionState& state, const FrameHeader& header) const {
    return header.publisher == state.publisher && header.worker_boot == state.boot;
  }

  void serve(TcpSocket socket, std::shared_ptr<TcpSocket> handle) {
    SessionState state;
    FrameAssembler assembler(config.limits);
    std::vector<std::byte> buffer(65536);
    bool running = true;
    while (running && !stopping.load()) {
      std::size_t received = 0;
      const Status read = socket.recv_some(buffer, received);
      if (!read.ok() || received == 0) {
        break;
      }
      const Status pushed = assembler.push(std::span<const std::byte>(buffer.data(), received));
      if (!pushed.ok()) {
        (void)send_error(socket, state, FrameHeader{}, pushed.code(), ReasonCode::OversizedVector,
                         pushed.detail());
        break;
      }
      for (;;) {
        Frame frame;
        bool produced = false;
        const Status popped = assembler.pop(frame, produced);
        if (!popped.ok()) {
          (void)send_error(socket, state, FrameHeader{}, popped.code(), ReasonCode::MalformedFrame,
                           popped.detail());
          running = false;
          break;
        }
        if (!produced) {
          break;
        }
        frames_handled.fetch_add(1);
        if (!handle_frame(socket, state, frame, running)) {
          break;
        }
      }
    }
    if (state.registered) {
      (void)coordinator->fence_on_session_loss(state.session);
    }
    {
      std::lock_guard<std::mutex> guard(mutex);
      if (state.registered) {
        sessions.erase(state.session.value());
      }
    }
    (void)handle;
    (void)socket.close();
  }

  [[nodiscard]] bool handle_frame(TcpSocket& socket, SessionState& state, const Frame& frame,
                                  bool& running) {
    const FrameHeader& header = frame.header;
    if (header.message == MessageId::Hello) {
      ByteReader reader(frame.payload);
      HelloPayload hello;
      if (!decode_hello(reader, config.limits, hello) || !reader.at_end()) {
        (void)send_error(socket, state, header, ErrorCode::Malformed, ReasonCode::MalformedFrame,
                         "hello payload is malformed");
        return false;
      }
      next_session.fetch_add(1);
      SessionState candidate;
      candidate.session = SessionId::from_value(next_session.load());
      candidate.publisher = hello.publisher;
      candidate.boot = hello.worker_boot;

      AuthorityContext context;
      context.epoch = coordinator->epoch();
      context.publisher = hello.publisher;
      context.worker_boot = hello.worker_boot;
      context.session = candidate.session;
      context.attempt = header.attempt.is_valid() ? header.attempt
                                                  : MutationAttemptId::from_value(1);
      context.request = header.request;
      context.scopes = 0;
      const Result<PublisherRegistration> registration = coordinator->register_publisher(
          context, hello.publisher, hello.worker_boot, hello.requested_scopes, candidate.session);
      HelloAckPayload ack;
      ack.epoch = coordinator->epoch();
      ack.session = candidate.session;
      ack.protocol_version = kProtocolVersionValue;
      if (!registration.ok()) {
        ack.accepted = false;
        ack.granted_scopes = 0;
        ByteWriter writer;
        encode_hello_ack(writer, ack);
        (void)send_frame(socket, MessageId::HelloAck, state, header, writer.buffer());
        (void)send_error(socket, state, header, registration.code(),
                         reason_class_of(ReasonCode::UnknownPublisher) == ReasonClass::CallerIdentity
                             ? ReasonCode::UnknownPublisher
                             : ReasonCode::ScopeNotAuthorized,
                         registration.detail());
        return false;
      }
      state = candidate;
      state.scopes = registration.value().scopes;
      state.registered = true;
      ack.accepted = true;
      ack.granted_scopes = state.scopes;
      ByteWriter writer;
      encode_hello_ack(writer, ack);
      return send_frame(socket, MessageId::HelloAck, state, header, writer.buffer()).ok();
    }

    if (!state.registered) {
      (void)send_error(socket, state, header, ErrorCode::Unauthorized,
                       ReasonCode::MissingAuthorityContext,
                       "default deny: the session has not registered a publisher");
      return false;
    }
    if (!identity_matches(state, header)) {
      (void)send_error(socket, state, header, ErrorCode::Fenced, ReasonCode::FencedWorkerBoot,
                       "frame identity does not match the registered session identity");
      return false;
    }

    const AuthorityContext context = context_for(state, header);
    switch (header.message) {
      case MessageId::PublishConstraintSet: {
        ByteReader reader(frame.payload);
        ConstraintSet set;
        if (!decode_constraint_set(reader, config.limits, set) || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed,
                           ReasonCode::MalformedConstraint, "constraint set payload is malformed");
          return true;
        }
        const Result<ConstraintSet> published =
            coordinator->publish_constraint_set(context, std::move(set));
        if (!published.ok()) {
          (void)send_error(socket, state, header, published.code(),
                           outcome_of(ReasonCode::MalformedConstraint) == Outcome::Malformed
                               ? ReasonCode::MalformedConstraint
                               : ReasonCode::MalformedConstraint,
                           published.detail());
          return true;
        }
        PublishConstraintSetAckPayload ack;
        ack.set_id = published.value().id;
        ack.generation = published.value().generation;
        ack.digest = published.value().digest;
        ByteWriter writer;
        encode_publish_ack(writer, ack);
        (void)send_frame(socket, MessageId::PublishConstraintSetAck, state, header, writer.buffer());
        return true;
      }
      case MessageId::ApplyLifecycle: {
        ByteReader reader(frame.payload);
        LifecycleRequestPayload request;
        if (!decode_lifecycle_request(reader, request) || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed, ReasonCode::MalformedFrame,
                           "lifecycle payload is malformed");
          return true;
        }
        const Result<ConstraintSet> applied =
            coordinator->apply_lifecycle(context, request.set_id, request.event);
        if (!applied.ok()) {
          (void)send_error(socket, state, header, applied.code(),
                           ReasonCode::ConstraintSetNotActive, applied.detail());
          return true;
        }
        PublishConstraintSetAckPayload ack;
        ack.set_id = applied.value().id;
        ack.generation = applied.value().generation;
        ack.digest = applied.value().digest;
        ByteWriter writer;
        encode_publish_ack(writer, ack);
        (void)send_frame(socket, MessageId::ApplyLifecycleAck, state, header, writer.buffer());
        return true;
      }
      case MessageId::EvaluateCandidates: {
        ByteReader reader(frame.payload);
        EvaluateCandidatesPayload request;
        if (!decode_evaluate_request(reader, config.limits, request) || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed,
                           ReasonCode::MalformedCandidate, "candidate payload is malformed");
          return true;
        }
        const Result<CommitOutcome> outcome = coordinator->evaluate(
            context, request.set_id, request.candidates, request.expected_generation);
        if (!outcome.ok()) {
          (void)send_error(socket, state, header, outcome.code(), ReasonCode::None,
                           outcome.detail());
          return true;
        }
        EvaluateCandidatesAckPayload ack;
        ack.batch = outcome.value().batch;
        ByteWriter writer;
        encode_evaluate_response(writer, ack);
        (void)send_frame(socket, MessageId::EvaluateCandidatesAck, state, header, writer.buffer());
        return true;
      }
      case MessageId::QueryDefinitions: {
        ByteReader reader(frame.payload);
        std::uint64_t set_id = 0;
        DefinitionsReportPayload report;
        if (!reader.u64(set_id) || set_id == 0 || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed, ReasonCode::MalformedFrame,
                           "definitions query payload is malformed");
          return true;
        }
        auto snapshot = coordinator->snapshot_definitions(ConstraintSetId::from_value(set_id));
        if (snapshot.ok()) {
          report.found = true;
          report.snapshot = std::move(snapshot.value());
        }
        ByteWriter writer;
        encode_definitions_report(writer, report);
        (void)send_frame(socket, MessageId::DefinitionsReport, state, header, writer.buffer());
        return true;
      }
      case MessageId::QueryResults: {
        ByteReader reader(frame.payload);
        std::uint64_t set_id = 0;
        ResultsReportPayload report;
        if (!reader.u64(set_id) || set_id == 0 || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed, ReasonCode::MalformedFrame,
                           "results query payload is malformed");
          return true;
        }
        auto snapshot = coordinator->snapshot_results(ConstraintSetId::from_value(set_id));
        if (snapshot.ok()) {
          report.found = true;
          report.snapshot = std::move(snapshot.value());
        }
        ByteWriter writer;
        encode_results_report(writer, report);
        (void)send_frame(socket, MessageId::ResultsReport, state, header, writer.buffer());
        return true;
      }
      case MessageId::QueryCurrentness: {
        ByteReader reader(frame.payload);
        std::uint64_t set_id = 0;
        CurrentnessReportPayload report;
        if (!reader.u64(set_id) || set_id == 0 || !reader.at_end()) {
          (void)send_error(socket, state, header, ErrorCode::Malformed, ReasonCode::MalformedFrame,
                           "currentness query payload is malformed");
          return true;
        }
        auto currentness = coordinator->currentness(ConstraintSetId::from_value(set_id));
        if (currentness.ok()) {
          report.found = true;
          report.report = std::move(currentness.value());
        }
        ByteWriter writer;
        encode_currentness_report(writer, report);
        (void)send_frame(socket, MessageId::CurrentnessReport, state, header, writer.buffer());
        return true;
      }
      case MessageId::Heartbeat: {
        (void)send_frame(socket, MessageId::Heartbeat, state, header, {});
        return true;
      }
      case MessageId::Shutdown: {
        (void)send_frame(socket, MessageId::Shutdown, state, header, {});
        running = false;
        return false;
      }
      case MessageId::Invalid:
      case MessageId::Hello:
      case MessageId::HelloAck:
      case MessageId::RegisterPublisher:
      case MessageId::RegisterPublisherAck:
      case MessageId::PublishConstraintSetAck:
      case MessageId::ApplyLifecycleAck:
      case MessageId::EvaluateCandidatesAck:
      case MessageId::DefinitionsReport:
      case MessageId::ResultsReport:
      case MessageId::CurrentnessReport:
      case MessageId::SessionFenced:
      case MessageId::ErrorReport:
      default:
        (void)send_error(socket, state, header, ErrorCode::ProtocolViolation,
                         ReasonCode::UnknownMessageId,
                         "message identifier is not valid in the client-to-server direction");
        return false;
    }
  }
};

CoordinatorServer::CoordinatorServer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

CoordinatorServer::~CoordinatorServer() { (void)stop(); }

Result<std::unique_ptr<CoordinatorServer>> CoordinatorServer::start(Coordinator& coordinator,
                                                                    const ServerConfig& config) {
  std::string why;
  if (!validate_limits(config.limits, why)) {
    return Result<std::unique_ptr<CoordinatorServer>>::failure(ErrorCode::InvalidArgument, why);
  }
  const Status started = SocketRuntime::initialize();
  if (!started.ok()) {
    return Result<std::unique_ptr<CoordinatorServer>>::failure(started.code(), started.detail());
  }
  auto impl = std::make_unique<Impl>();
  impl->coordinator = &coordinator;
  impl->config = config;
  const Status bound = impl->listener.bind_loopback(config.port);
  if (!bound.ok()) {
    return Result<std::unique_ptr<CoordinatorServer>>::failure(bound.code(), bound.detail());
  }
  return Result<std::unique_ptr<CoordinatorServer>>::success(
      std::unique_ptr<CoordinatorServer>(new CoordinatorServer(std::move(impl))));
}

Status CoordinatorServer::run() {
  while (!impl_->stopping.load()) {
    TcpSocket socket;
    const Status accepted = impl_->listener.accept(socket);
    if (!accepted.ok()) {
      if (impl_->stopping.load()) {
        break;
      }
      return accepted;
    }
    if (impl_->active_session_count() >= impl_->config.limits.max_sessions) {
      (void)socket.close();
      continue;
    }
    auto handle = std::make_shared<TcpSocket>(std::move(socket));
    impl_->sessions_accepted.fetch_add(1);
    impl_->threads.emplace_back([this, handle]() {
      TcpSocket local = std::move(*handle);
      impl_->serve(std::move(local), handle);
    });
  }
  return Status::success();
}

Status CoordinatorServer::stop() {
  impl_->stopping.store(true);
  (void)impl_->listener.close();
  {
    std::lock_guard<std::mutex> guard(impl_->mutex);
    for (auto& entry : impl_->sessions) {
      entry.second->abort();
    }
  }
  for (std::thread& thread : impl_->threads) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  impl_->threads.clear();
  return Status::success();
}

std::uint16_t CoordinatorServer::port() const noexcept { return impl_->listener.port(); }

std::size_t CoordinatorServer::sessions_accepted() const noexcept {
  return impl_->sessions_accepted.load();
}

std::size_t CoordinatorServer::frames_handled() const noexcept {
  return impl_->frames_handled.load();
}

std::size_t CoordinatorServer::active_sessions() const noexcept {
  return impl_->active_session_count();
}

}  // namespace crf
