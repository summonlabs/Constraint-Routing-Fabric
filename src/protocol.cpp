// Constraint Routing Fabric -- versioned wire protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/protocol.hpp"

#include <array>
#include <cstring>
#include <string>

#include "constraint_routing_fabric/version.hpp"

namespace crf {
namespace {

/// Bytes before the integrity trailer: magic through scopes.
constexpr std::size_t kSemanticHeaderBytes = 60;
constexpr std::size_t kTrailerBytes = 4 + Digest256::kSize;
constexpr std::size_t kHeaderBytes = kSemanticHeaderBytes + kTrailerBytes;

[[nodiscard]] std::span<const std::byte> semantic_header(std::span<const std::byte> raw) {
  return raw.subspan(0, kSemanticHeaderBytes);
}

[[nodiscard]] Digest256 integrity_digest(std::span<const std::byte> header,
                                        std::span<const std::byte> payload) {
  Sha256 sha;
  sha.update(header);
  sha.update(payload);
  return sha.finish();
}

[[nodiscard]] std::uint32_t integrity_crc(std::span<const std::byte> header,
                                          std::span<const std::byte> payload) {
  std::vector<std::byte> joined(header.begin(), header.end());
  joined.insert(joined.end(), payload.begin(), payload.end());
  return crc32c(joined);
}

[[nodiscard]] bool known_family(std::uint8_t raw) noexcept { return raw <= 8; }

}  // namespace

const char* to_string(MessageId id) noexcept {
  switch (id) {
    case MessageId::Invalid: return "Invalid";
    case MessageId::Hello: return "Hello";
    case MessageId::HelloAck: return "HelloAck";
    case MessageId::RegisterPublisher: return "RegisterPublisher";
    case MessageId::RegisterPublisherAck: return "RegisterPublisherAck";
    case MessageId::PublishConstraintSet: return "PublishConstraintSet";
    case MessageId::PublishConstraintSetAck: return "PublishConstraintSetAck";
    case MessageId::ApplyLifecycle: return "ApplyLifecycle";
    case MessageId::ApplyLifecycleAck: return "ApplyLifecycleAck";
    case MessageId::EvaluateCandidates: return "EvaluateCandidates";
    case MessageId::EvaluateCandidatesAck: return "EvaluateCandidatesAck";
    case MessageId::QueryDefinitions: return "QueryDefinitions";
    case MessageId::DefinitionsReport: return "DefinitionsReport";
    case MessageId::QueryResults: return "QueryResults";
    case MessageId::ResultsReport: return "ResultsReport";
    case MessageId::QueryCurrentness: return "QueryCurrentness";
    case MessageId::CurrentnessReport: return "CurrentnessReport";
    case MessageId::Heartbeat: return "Heartbeat";
    case MessageId::SessionFenced: return "SessionFenced";
    case MessageId::ErrorReport: return "ErrorReport";
    case MessageId::Shutdown: return "Shutdown";
  }
  return "Unknown";
}

bool is_known_message(std::uint16_t raw) noexcept {
  return raw >= static_cast<std::uint16_t>(MessageId::Hello) &&
         raw <= static_cast<std::uint16_t>(MessageId::Shutdown);
}

std::size_t frame_size(std::uint32_t payload_length) noexcept {
  return kHeaderBytes + payload_length;
}

void encode_frame_header(ByteWriter& writer, const FrameHeader& header) {
  writer.put_u32(kWireMagic);
  writer.put_u16(header.protocol_version);
  writer.put_u16(static_cast<std::uint16_t>(header.message));
  writer.put_u16(header.flags);
  writer.put_u16(0);
  writer.put_u32(header.payload_length);
  writer.put_u64(header.epoch.value());
  writer.put_u64(header.publisher.value());
  writer.put_u64(header.worker_boot.value());
  writer.put_u64(header.attempt.value());
  writer.put_u64(header.request.value());
  writer.put_u32(header.scopes);
}

bool decode_frame_header(ByteReader& reader, FrameHeader& out) {
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t message = 0;
  std::uint16_t flags = 0;
  std::uint16_t reserved = 0;
  std::uint32_t payload_length = 0;
  std::uint64_t epoch = 0;
  std::uint64_t publisher = 0;
  std::uint64_t boot = 0;
  std::uint64_t attempt = 0;
  std::uint64_t request = 0;
  if (!reader.u32(magic) || !reader.u16(version) || !reader.u16(message) || !reader.u16(flags) ||
      !reader.u16(reserved) || !reader.u32(payload_length) || !reader.u64(epoch) ||
      !reader.u64(publisher) || !reader.u64(boot) || !reader.u64(attempt) || !reader.u64(request) ||
      !reader.u32(out.scopes)) {
    return false;
  }
  if (magic != kWireMagic || reserved != 0 || !is_known_message(message)) {
    reader.fail();
    return false;
  }
  if (epoch != 0 && !CoordinatorEpoch::is_representable(epoch)) {
    reader.fail();
    return false;
  }
  out.protocol_version = version;
  out.message = static_cast<MessageId>(message);
  out.flags = flags;
  out.payload_length = payload_length;
  out.epoch = epoch == 0 ? CoordinatorEpoch{} : CoordinatorEpoch::from_value(epoch);
  out.publisher = PublisherId::from_value(publisher);
  out.worker_boot = WorkerBootId::from_value(boot);
  out.attempt = MutationAttemptId::from_value(attempt);
  out.request = RequestId::from_value(request);
  return true;
}

Status encode_frame(const Frame& frame, const Limits& limits, std::vector<std::byte>& out) {
  if (frame.payload.size() > limits.max_frame_bytes) {
    return Status::failure(ErrorCode::ResourceLimit, "frame payload exceeds the configured limit");
  }
  FrameHeader header = frame.header;
  header.protocol_version = kProtocolVersionValue;
  header.payload_length = static_cast<std::uint32_t>(frame.payload.size());
  if (header.message == MessageId::Invalid) {
    return Status::failure(ErrorCode::InvalidArgument, "frame message identifier is not set");
  }
  ByteWriter writer;
  encode_frame_header(writer, header);
  const std::vector<std::byte> header_bytes = writer.buffer();
  writer.put_raw(frame.payload);
  const std::span<const std::byte> semantic(header_bytes.data(), kSemanticHeaderBytes);
  writer.put_u32(integrity_crc(semantic, frame.payload));
  const Digest256 digest = integrity_digest(semantic, frame.payload);
  writer.put_raw(std::span<const std::byte>(digest.data(), Digest256::kSize));
  out = writer.buffer();
  return Status::success();
}

Status decode_frame(std::span<const std::byte> raw, const Limits& limits, Frame& out) {
  if (raw.size() < kHeaderBytes) {
    return Status::failure(ErrorCode::Truncated, "frame is shorter than its header");
  }
  ByteReader reader(raw);
  FrameHeader header;
  if (!decode_frame_header(reader, header)) {
    return Status::failure(ErrorCode::Malformed, "frame header is malformed");
  }
  if (header.protocol_version != kProtocolVersionValue) {
    return Status::failure(ErrorCode::UnsupportedVersion, "frame protocol version is not supported");
  }
  if (header.payload_length > limits.max_frame_bytes) {
    return Status::failure(ErrorCode::ResourceLimit, "frame declares an oversized payload");
  }
  if (raw.size() != frame_size(header.payload_length)) {
    return Status::failure(raw.size() < frame_size(header.payload_length) ? ErrorCode::Truncated
                                                                         : ErrorCode::TrailingBytes,
                           "frame length does not match its declared payload length");
  }
  // Layout: semantic header, payload, then the integrity trailer. The trailer
  // is not part of the semantic header, so the payload starts immediately after
  // the semantic header rather than after the whole fixed frame prefix.
  const std::span<const std::byte> semantic = semantic_header(raw);
  const std::span<const std::byte> payload =
      raw.subspan(kSemanticHeaderBytes, header.payload_length);
  const std::span<const std::byte> trailer =
      raw.subspan(kSemanticHeaderBytes + header.payload_length);
  if (integrity_crc(semantic, payload) != [&trailer] {
        std::uint32_t value = 0;
        for (std::size_t index = 0; index < 4; ++index) {
          value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(trailer[index]))
                   << (index * 8);
        }
        return value;
      }()) {
    return Status::failure(ErrorCode::IntegrityMismatch, "frame checksum does not match");
  }
  const Digest256 expected = integrity_digest(semantic, payload);
  for (std::size_t index = 0; index < Digest256::kSize; ++index) {
    if (std::to_integer<std::uint8_t>(trailer[4 + index]) !=
        std::to_integer<std::uint8_t>(expected.data()[index])) {
      return Status::failure(ErrorCode::IntegrityMismatch, "frame digest does not match");
    }
  }
  out.header = header;
  out.payload.assign(payload.begin(), payload.end());
  return Status::success();
}

Status FrameAssembler::fail(ErrorCode code, std::string detail) {
  failed_ = true;
  buffer_.clear();
  return Status::failure(code, std::move(detail));
}

Status FrameAssembler::push(std::span<const std::byte> chunk) {
  if (failed_) {
    return Status::failure(ErrorCode::ProtocolViolation, "frame assembler is in a failed state");
  }
  if (buffer_.size() + chunk.size() > limits_.max_frame_assembly_bytes) {
    return fail(ErrorCode::ResourceLimit, "frame assembly buffer exceeds the configured limit");
  }
  buffer_.insert(buffer_.end(), chunk.begin(), chunk.end());
  return Status::success();
}

Status FrameAssembler::pop(Frame& out, bool& produced) {
  produced = false;
  if (failed_) {
    return Status::failure(ErrorCode::ProtocolViolation, "frame assembler is in a failed state");
  }
  if (buffer_.size() < kHeaderBytes) {
    return Status::success();
  }
  std::array<std::byte, kHeaderBytes> header_bytes{};
  for (std::size_t index = 0; index < kHeaderBytes; ++index) {
    header_bytes[index] = buffer_[index];
  }
  ByteReader header_reader(std::span<const std::byte>(header_bytes.data(), kSemanticHeaderBytes));
  FrameHeader header;
  if (!decode_frame_header(header_reader, header)) {
    return fail(ErrorCode::Malformed, "started frame header is malformed");
  }
  if (header.protocol_version != kProtocolVersionValue) {
    return fail(ErrorCode::UnsupportedVersion, "started frame declares an unsupported protocol version");
  }
  if (header.payload_length > limits_.max_frame_bytes) {
    return fail(ErrorCode::ResourceLimit, "started frame declares an oversized payload");
  }
  const std::size_t total = frame_size(header.payload_length);
  if (buffer_.size() < total) {
    return Status::success();
  }
  std::vector<std::byte> raw;
  raw.reserve(total);
  for (std::size_t index = 0; index < total; ++index) {
    raw.push_back(buffer_.front());
    buffer_.pop_front();
  }
  const Status decoded = decode_frame(raw, limits_, out);
  if (!decoded.ok()) {
    return fail(decoded.code(), decoded.detail());
  }
  produced = true;
  return Status::success();
}

void FrameAssembler::reset() {
  buffer_.clear();
  failed_ = false;
}

void FrameAssembler::reset_after_violation() {
  reset();
}

void encode_hello(ByteWriter& writer, const HelloPayload& payload) {
  writer.put_u64(payload.publisher.value());
  writer.put_u64(payload.worker_boot.value());
  writer.put_u32(payload.requested_scopes);
  writer.put_string(payload.client_name);
}

bool decode_hello(ByteReader& reader, const Limits& limits, HelloPayload& out) {
  std::uint64_t publisher = 0;
  std::uint64_t boot = 0;
  std::uint32_t scopes = 0;
  if (!reader.u64(publisher) || !reader.u64(boot) || !reader.u32(scopes)) {
    return false;
  }
  if (publisher == 0 || boot == 0) {
    reader.fail();
    return false;
  }
  if (!reader.string(out.client_name) || out.client_name.size() > limits.max_name_bytes) {
    reader.fail();
    return false;
  }
  out.publisher = PublisherId::from_value(publisher);
  out.worker_boot = WorkerBootId::from_value(boot);
  out.requested_scopes = scopes;
  return true;
}

void encode_hello_ack(ByteWriter& writer, const HelloAckPayload& payload) {
  writer.put_u64(payload.epoch.value());
  writer.put_u64(payload.session.value());
  writer.put_u32(payload.granted_scopes);
  writer.put_u16(payload.protocol_version);
  writer.put_bool(payload.accepted);
  writer.put_u8(0);
}

bool decode_hello_ack(ByteReader& reader, HelloAckPayload& out) {
  std::uint64_t epoch = 0;
  std::uint64_t session = 0;
  std::uint32_t scopes = 0;
  std::uint16_t version = 0;
  std::uint8_t padding = 0;
  if (!reader.u64(epoch) || !reader.u64(session) || !reader.u32(scopes) || !reader.u16(version) ||
      !reader.boolean(out.accepted) || !reader.u8(padding)) {
    return false;
  }
  if (padding != 0 || (epoch != 0 && !CoordinatorEpoch::is_representable(epoch))) {
    reader.fail();
    return false;
  }
  out.epoch = epoch == 0 ? CoordinatorEpoch{} : CoordinatorEpoch::from_value(epoch);
  out.session = SessionId::from_value(session);
  out.granted_scopes = scopes;
  out.protocol_version = version;
  return true;
}

void encode_evaluate_request(ByteWriter& writer, const EvaluateCandidatesPayload& payload) {
  writer.put_u64(payload.set_id.value());
  writer.put_u64(payload.expected_generation.value());
  writer.put_u32(static_cast<std::uint32_t>(payload.candidates.size()));
  for (const CandidatePath& candidate : payload.candidates) {
    encode_candidate(writer, candidate);
  }
}

bool decode_evaluate_request(ByteReader& reader, const Limits& limits,
                             EvaluateCandidatesPayload& out) {
  std::uint64_t set_id = 0;
  std::uint64_t generation = 0;
  if (!reader.u64(set_id) || !reader.u64(generation)) {
    return false;
  }
  // A zero expected generation means "no expectation", which is a legitimate
  // request; a non-zero value must be a representable generation.
  if (set_id == 0 ||
      (generation != 0 && !ConstraintSetGeneration::is_representable(generation))) {
    reader.fail();
    return false;
  }
  out.set_id = ConstraintSetId::from_value(set_id);
  out.expected_generation =
      generation == 0 ? ConstraintSetGeneration{} : ConstraintSetGeneration::from_value(generation);
  std::uint32_t count = 0;
  if (!reader.bounded_length(limits.max_candidates_per_evaluation, count)) {
    return false;
  }
  out.candidates.clear();
  out.candidates.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    CandidatePath candidate;
    if (!decode_candidate(reader, limits, candidate)) {
      return false;
    }
    out.candidates.push_back(std::move(candidate));
  }
  return true;
}

void encode_evaluation_batch(ByteWriter& writer, const EvaluationBatch& batch) {
  writer.put_u64(batch.set_id.value());
  writer.put_u64(batch.set_generation.value());
  writer.put_u64(batch.generation.value());
  writer.put_u16(static_cast<std::uint16_t>(batch.batch_outcome));
  writer.put_u16(static_cast<std::uint16_t>(batch.primary_batch_reason));
  writer.put_bool(batch.has_admissible);
  writer.put_u8(0);
  writer.put_u32(static_cast<std::uint32_t>(batch.records.size()));
  for (const EvaluationRecord& record : batch.records) {
    encode_evaluation(writer, record);
  }
  writer.put_u32(static_cast<std::uint32_t>(batch.admissible_order.size()));
  for (const RankedCandidate& entry : batch.admissible_order) {
    writer.put_u64(entry.path.value());
    writer.put_u32(entry.record_index);
  }
}

bool decode_evaluation_batch(ByteReader& reader, const Limits& limits, EvaluationBatch& out) {
  std::uint64_t set_id = 0;
  std::uint64_t set_generation = 0;
  std::uint64_t generation = 0;
  std::uint16_t batch_outcome = 0;
  std::uint16_t primary = 0;
  std::uint8_t padding = 0;
  if (!reader.u64(set_id) || !reader.u64(set_generation) || !reader.u64(generation) ||
      !reader.u16(batch_outcome) || !reader.u16(primary) || !reader.boolean(out.has_admissible) ||
      !reader.u8(padding)) {
    return false;
  }
  if (padding != 0 || batch_outcome > 2) {
    reader.fail();
    return false;
  }
  if (set_id != 0) {
    out.set_id = ConstraintSetId::from_value(set_id);
  }
  if (ConstraintSetGeneration::is_representable(set_generation)) {
    out.set_generation = ConstraintSetGeneration::from_value(set_generation);
  }
  if (EvaluationGeneration::is_representable(generation)) {
    out.generation = EvaluationGeneration::from_value(generation);
  }
  out.batch_outcome = static_cast<BatchOutcome>(batch_outcome);
  out.primary_batch_reason = static_cast<ReasonCode>(primary);
  std::uint32_t count = 0;
  if (!reader.bounded_length(limits.max_candidates_per_evaluation, count)) {
    return false;
  }
  out.records.clear();
  out.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    EvaluationRecord record;
    if (!decode_evaluation(reader, limits, record)) {
      return false;
    }
    out.records.push_back(std::move(record));
  }
  if (!reader.bounded_length(limits.max_candidates_per_evaluation, count)) {
    return false;
  }
  out.admissible_order.clear();
  out.admissible_order.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint64_t path = 0;
    RankedCandidate entry;
    if (!reader.u64(path) || !reader.u32(entry.record_index) || path == 0) {
      reader.fail();
      return false;
    }
    if (entry.record_index >= out.records.size()) {
      reader.fail();
      return false;
    }
    entry.path = PathId::from_value(path);
    out.admissible_order.push_back(entry);
  }
  return true;
}

void encode_evaluate_response(ByteWriter& writer, const EvaluateCandidatesAckPayload& payload) {
  encode_evaluation_batch(writer, payload.batch);
}

bool decode_evaluate_response(ByteReader& reader, const Limits& limits,
                              EvaluateCandidatesAckPayload& out) {
  return decode_evaluation_batch(reader, limits, out.batch);
}

void encode_error_report(ByteWriter& writer, const ErrorReportPayload& payload) {
  writer.put_u32(static_cast<std::uint32_t>(payload.code));
  writer.put_u16(static_cast<std::uint16_t>(payload.reason));
  writer.put_u16(0);
  writer.put_string(payload.detail);
}

bool decode_error_report(ByteReader& reader, const Limits& limits, ErrorReportPayload& out) {
  std::uint32_t code = 0;
  std::uint16_t reason = 0;
  std::uint16_t padding = 0;
  if (!reader.u32(code) || !reader.u16(reason) || !reader.u16(padding)) {
    return false;
  }
  if (code > static_cast<std::uint32_t>(ErrorCode::Internal) || padding != 0) {
    reader.fail();
    return false;
  }
  if (!reader.string(out.detail) || out.detail.size() > limits.max_detail_bytes) {
    reader.fail();
    return false;
  }
  out.code = static_cast<ErrorCode>(code);
  out.reason = static_cast<ReasonCode>(reason);
  return true;
}

void encode_publish_ack(ByteWriter& writer, const PublishConstraintSetAckPayload& payload) {
  writer.put_u64(payload.set_id.value());
  writer.put_u64(payload.generation.value());
  writer.put_raw(std::span<const std::byte>(payload.digest.data(), Digest256::kSize));
}

bool decode_publish_ack(ByteReader& reader, PublishConstraintSetAckPayload& out) {
  std::uint64_t set_id = 0;
  std::uint64_t generation = 0;
  if (!reader.u64(set_id) || !reader.u64(generation)) {
    return false;
  }
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes))) {
    return false;
  }
  if (set_id == 0 || !ConstraintSetGeneration::is_representable(generation)) {
    reader.fail();
    return false;
  }
  out.set_id = ConstraintSetId::from_value(set_id);
  out.generation = ConstraintSetGeneration::from_value(generation);
  out.digest = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  return true;
}

}  // namespace crf
