// Constraint Routing Fabric -- worker client.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/worker.hpp"

#include <atomic>
#include <vector>

#include "constraint_routing_fabric/messages.hpp"
#include "constraint_routing_fabric/protocol.hpp"

namespace crf {
namespace {

[[nodiscard]] std::uint64_t mix(std::uint64_t value) noexcept {
  value += 0x9e3779b97f4a7c15ull;
  value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
  value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
  return value ^ (value >> 31);
}

}  // namespace

WorkerClient::WorkerClient() = default;

WorkerClient::~WorkerClient() { (void)close(); }

Result<std::unique_ptr<WorkerClient>> WorkerClient::connect(const WorkerConfig& config,
                                                            const Limits& limits) {
  std::string why;
  if (!validate_limits(limits, why)) {
    return Result<std::unique_ptr<WorkerClient>>::failure(ErrorCode::InvalidArgument, why);
  }
  const Status started = SocketRuntime::initialize();
  if (!started.ok()) {
    return Result<std::unique_ptr<WorkerClient>>::failure(started.code(), started.detail());
  }
  std::unique_ptr<WorkerClient> client(new WorkerClient());
  client->limits_ = limits;
  client->publisher_ = config.publisher;
  client->boot_ =
      config.boot.is_valid() ? config.boot : AuthorityRegistry::fresh_worker_boot();
  const Status connected = client->socket_.connect_loopback(config.port);
  if (!connected.ok()) {
    return Result<std::unique_ptr<WorkerClient>>::failure(connected.code(), connected.detail());
  }

  HelloPayload hello;
  hello.publisher = config.publisher;
  hello.worker_boot = client->boot_;
  hello.requested_scopes = config.requested_scopes;
  hello.client_name = config.client_name;
  ByteWriter writer;
  encode_hello(writer, hello);

  Frame request;
  request.header.message = MessageId::Hello;
  request.header.epoch = CoordinatorEpoch{};
  request.header.publisher = config.publisher;
  request.header.worker_boot = client->boot_;
  request.header.attempt = MutationAttemptId::from_value(1);
  request.header.request = RequestId::from_value(1);
  request.header.scopes = config.requested_scopes;
  request.payload = writer.buffer();

  std::vector<std::byte> encoded;
  const Status frame_status = encode_frame(request, limits, encoded);
  if (!frame_status.ok()) {
    return Result<std::unique_ptr<WorkerClient>>::failure(frame_status.code(), frame_status.detail());
  }
  const Status sent = client->socket_.send_all(encoded);
  if (!sent.ok()) {
    return Result<std::unique_ptr<WorkerClient>>::failure(sent.code(), sent.detail());
  }

  FrameAssembler assembler(limits);
  Frame response;
  std::vector<std::byte> buffer(65536);
  for (;;) {
    bool produced = false;
    const Status popped = assembler.pop(response, produced);
    if (!popped.ok()) {
      return Result<std::unique_ptr<WorkerClient>>::failure(popped.code(), popped.detail());
    }
    if (produced) {
      break;
    }
    std::size_t received = 0;
    const Status read = client->socket_.recv_some(buffer, received);
    if (!read.ok()) {
      return Result<std::unique_ptr<WorkerClient>>::failure(read.code(), read.detail());
    }
    if (received == 0) {
      return Result<std::unique_ptr<WorkerClient>>::failure(
          ErrorCode::TransportFailure, "coordinator closed the connection during the handshake");
    }
    const Status pushed = assembler.push(std::span<const std::byte>(buffer.data(), received));
    if (!pushed.ok()) {
      return Result<std::unique_ptr<WorkerClient>>::failure(pushed.code(), pushed.detail());
    }
  }
  if (response.header.message != MessageId::HelloAck) {
    return Result<std::unique_ptr<WorkerClient>>::failure(
        ErrorCode::ProtocolViolation, "coordinator did not answer the handshake with a hello acknowledgement");
  }
  ByteReader reader(response.payload);
  HelloAckPayload ack;
  if (!decode_hello_ack(reader, ack)) {
    return Result<std::unique_ptr<WorkerClient>>::failure(ErrorCode::Malformed,
                                                          "hello acknowledgement is malformed");
  }
  if (!ack.accepted) {
    return Result<std::unique_ptr<WorkerClient>>::failure(
        ErrorCode::Unauthorized, "default deny: the coordinator refused the publisher registration");
  }
  client->session_ = ack.session;
  client->epoch_ = ack.epoch;
  client->granted_scopes_ = ack.granted_scopes;
  return Result<std::unique_ptr<WorkerClient>>::success(std::move(client));
}

AuthorityContext WorkerClient::next_context() {
  ++attempt_counter_;
  AuthorityContext context;
  context.epoch = epoch_;
  context.publisher = publisher_;
  context.worker_boot = boot_;
  context.session = session_;
  context.scopes = granted_scopes_;
  std::uint64_t value = mix(boot_.value() ^ (attempt_counter_ * 0x9e3779b97f4a7c15ull));
  if (value == 0) {
    value = 1;
  }
  context.attempt = MutationAttemptId::from_value(value);
  context.request = RequestId::from_value(attempt_counter_);
  return context;
}

Result<Frame> WorkerClient::round_trip(MessageId request_id, const std::vector<std::byte>& payload) {
  if (!session_.is_valid()) {
    return Result<Frame>::failure(ErrorCode::Unauthorized, "session is not established");
  }
  ++attempt_counter_;
  Frame request;
  request.header.message = request_id;
  request.header.epoch = epoch_;
  request.header.publisher = publisher_;
  request.header.worker_boot = boot_;
  request.header.scopes = granted_scopes_;
  std::uint64_t attempt = mix(boot_.value() ^ (attempt_counter_ * 0x9e3779b97f4a7c15ull));
  if (attempt == 0) {
    attempt = 1;
  }
  request.header.attempt = MutationAttemptId::from_value(attempt);
  request.header.request = RequestId::from_value(attempt_counter_);
  request.payload = payload;

  std::vector<std::byte> encoded;
  const Status frame_status = encode_frame(request, limits_, encoded);
  if (!frame_status.ok()) {
    return Result<Frame>::failure(frame_status.code(), frame_status.detail());
  }
  const Status sent = socket_.send_all(encoded);
  if (!sent.ok()) {
    return Result<Frame>::failure(sent.code(), sent.detail());
  }

  FrameAssembler assembler(limits_);
  std::vector<std::byte> buffer(65536);
  for (;;) {
    Frame response;
    bool produced = false;
    const Status popped = assembler.pop(response, produced);
    if (!popped.ok()) {
      return Result<Frame>::failure(popped.code(), popped.detail());
    }
    if (produced) {
      if (!(response.header.request == request.header.request)) {
        return Result<Frame>::failure(ErrorCode::ProtocolViolation,
                                      "response request identity does not match the request");
      }
      if (response.header.message == MessageId::ErrorReport) {
        ByteReader reader(response.payload);
        ErrorReportPayload report;
        if (!decode_error_report(reader, limits_, report)) {
          return Result<Frame>::failure(ErrorCode::Malformed, "error report is malformed");
        }
        return Result<Frame>::failure(report.code, report.detail);
      }
      return Result<Frame>::success(std::move(response));
    }
    std::size_t received = 0;
    const Status read = socket_.recv_some(buffer, received);
    if (!read.ok()) {
      return Result<Frame>::failure(read.code(), read.detail());
    }
    if (received == 0) {
      return Result<Frame>::failure(ErrorCode::TransportFailure, "coordinator closed the connection");
    }
    const Status pushed = assembler.push(std::span<const std::byte>(buffer.data(), received));
    if (!pushed.ok()) {
      return Result<Frame>::failure(pushed.code(), pushed.detail());
    }
  }
}

Result<ConstraintSet> WorkerClient::publish_constraint_set(const ConstraintSet& set) {
  ByteWriter writer;
  encode_constraint_set(writer, set);
  const Result<Frame> response = round_trip(MessageId::PublishConstraintSet, writer.buffer());
  if (!response.ok()) {
    return Result<ConstraintSet>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  PublishConstraintSetAckPayload ack;
  if (!decode_publish_ack(reader, ack)) {
    return Result<ConstraintSet>::failure(ErrorCode::Malformed, "publication acknowledgement is malformed");
  }
  ConstraintSet published = set;
  published.id = ack.set_id;
  published.generation = ack.generation;
  published.digest = ack.digest;
  return Result<ConstraintSet>::success(std::move(published));
}

Result<ConstraintSet> WorkerClient::apply_lifecycle(ConstraintSetId set_id, LifecycleEvent event) {
  ByteWriter writer;
  LifecycleRequestPayload payload;
  payload.set_id = set_id;
  payload.event = event;
  encode_lifecycle_request(writer, payload);
  const Result<Frame> response = round_trip(MessageId::ApplyLifecycle, writer.buffer());
  if (!response.ok()) {
    return Result<ConstraintSet>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  PublishConstraintSetAckPayload ack;
  if (!decode_publish_ack(reader, ack)) {
    return Result<ConstraintSet>::failure(ErrorCode::Malformed, "lifecycle acknowledgement is malformed");
  }
  ConstraintSet result;
  result.id = ack.set_id;
  result.generation = ack.generation;
  result.digest = ack.digest;
  return Result<ConstraintSet>::success(std::move(result));
}

Result<CommitOutcome> WorkerClient::evaluate(ConstraintSetId set_id,
                                             std::span<const CandidatePath> candidates) {
  ByteWriter writer;
  EvaluateCandidatesPayload payload;
  payload.set_id = set_id;
  payload.expected_generation = ConstraintSetGeneration{};
  payload.candidates.assign(candidates.begin(), candidates.end());
  encode_evaluate_request(writer, payload);
  const Result<Frame> response = round_trip(MessageId::EvaluateCandidates, writer.buffer());
  if (!response.ok()) {
    return Result<CommitOutcome>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  EvaluateCandidatesAckPayload ack;
  if (!decode_evaluate_response(reader, limits_, ack)) {
    return Result<CommitOutcome>::failure(ErrorCode::Malformed, "evaluation response is malformed");
  }
  CommitOutcome outcome;
  outcome.batch = std::move(ack.batch);
  outcome.committed = true;
  return Result<CommitOutcome>::success(std::move(outcome));
}

Result<DefinitionsSnapshot> WorkerClient::query_definitions(ConstraintSetId set_id) {
  ByteWriter writer;
  writer.put_u64(set_id.value());
  const Result<Frame> response = round_trip(MessageId::QueryDefinitions, writer.buffer());
  if (!response.ok()) {
    return Result<DefinitionsSnapshot>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  DefinitionsReportPayload report;
  if (!decode_definitions_report(reader, limits_, report) || !report.found) {
    return Result<DefinitionsSnapshot>::failure(ErrorCode::NotFound,
                                                "coordinator has no such constraint set");
  }
  return Result<DefinitionsSnapshot>::success(std::move(report.snapshot));
}

Result<ResultsSnapshot> WorkerClient::query_results(ConstraintSetId set_id) {
  ByteWriter writer;
  writer.put_u64(set_id.value());
  const Result<Frame> response = round_trip(MessageId::QueryResults, writer.buffer());
  if (!response.ok()) {
    return Result<ResultsSnapshot>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  ResultsReportPayload report;
  if (!decode_results_report(reader, limits_, report) || !report.found) {
    return Result<ResultsSnapshot>::failure(ErrorCode::NotFound,
                                            "coordinator has no such constraint set");
  }
  return Result<ResultsSnapshot>::success(std::move(report.snapshot));
}

Result<CurrentnessReport> WorkerClient::query_currentness(ConstraintSetId set_id) {
  ByteWriter writer;
  writer.put_u64(set_id.value());
  const Result<Frame> response = round_trip(MessageId::QueryCurrentness, writer.buffer());
  if (!response.ok()) {
    return Result<CurrentnessReport>::failure(response.code(), response.detail());
  }
  ByteReader reader(response.value().payload);
  CurrentnessReportPayload report;
  if (!decode_currentness_report(reader, limits_, report) || !report.found) {
    return Result<CurrentnessReport>::failure(ErrorCode::NotFound,
                                              "coordinator has no such constraint set");
  }
  return Result<CurrentnessReport>::success(std::move(report.report));
}

Status WorkerClient::heartbeat() {
  const Result<Frame> response = round_trip(MessageId::Heartbeat, {});
  if (!response.ok()) {
    return Status::failure(response.code(), response.detail());
  }
  return Status::success();
}

Status WorkerClient::close() {
  if (socket_.valid()) {
    (void)round_trip(MessageId::Shutdown, {});
    (void)socket_.close();
  }
  session_ = SessionId{};
  return Status::success();
}

}  // namespace crf
