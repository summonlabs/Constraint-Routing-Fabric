// Constraint Routing Fabric -- versioned distributed wire protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_PROTOCOL_HPP
#define CONSTRAINT_ROUTING_FABRIC_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <vector>

#include "constraint_routing_fabric/authority.hpp"
#include "constraint_routing_fabric/candidate.hpp"
#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Stable numeric message identifiers. Never renumbered.
enum class MessageId : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  RegisterPublisher = 3,
  RegisterPublisherAck = 4,
  PublishConstraintSet = 5,
  PublishConstraintSetAck = 6,
  ApplyLifecycle = 7,
  ApplyLifecycleAck = 8,
  EvaluateCandidates = 9,
  EvaluateCandidatesAck = 10,
  QueryDefinitions = 11,
  DefinitionsReport = 12,
  QueryResults = 13,
  ResultsReport = 14,
  QueryCurrentness = 15,
  CurrentnessReport = 16,
  Heartbeat = 17,
  SessionFenced = 18,
  ErrorReport = 19,
  Shutdown = 20,
};

[[nodiscard]] const char* to_string(MessageId id) noexcept;
[[nodiscard]] bool is_known_message(std::uint16_t raw) noexcept;

inline constexpr std::uint16_t kProtocolVersionValue = 1;

/// Fixed semantic header. Integrity covers this header together with the
/// payload, so a header edit is detected.
struct FrameHeader {
  std::uint16_t protocol_version{kProtocolVersionValue};
  MessageId message{MessageId::Invalid};
  std::uint16_t flags{0};
  std::uint32_t payload_length{0};
  CoordinatorEpoch epoch{};
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  MutationAttemptId attempt{};
  RequestId request{};
  AuthorityScopeMask scopes{0};
};

struct Frame {
  FrameHeader header{};
  std::vector<std::byte> payload{};
};

/// Total encoded size of a frame with the given payload length.
[[nodiscard]] std::size_t frame_size(std::uint32_t payload_length) noexcept;

void encode_frame_header(ByteWriter& writer, const FrameHeader& header);
[[nodiscard]] bool decode_frame_header(ByteReader& reader, FrameHeader& out);

[[nodiscard]] Status encode_frame(const Frame& frame, const Limits& limits, std::vector<std::byte>& out);
[[nodiscard]] Status decode_frame(std::span<const std::byte> raw, const Limits& limits, Frame& out);

/// Reassembles arbitrarily fragmented transport reads into whole frames with a
/// hard bound on started-frame bytes. A peer that sends a partial frame cannot
/// pin memory: the assembler fails closed instead of growing without limit.
class FrameAssembler {
 public:
  explicit FrameAssembler(const Limits& limits) : limits_(limits) {}

  [[nodiscard]] Status push(std::span<const std::byte> chunk);
  /// Pops one complete frame. Returns false when more bytes are needed.
  [[nodiscard]] Status pop(Frame& out, bool& produced);
  [[nodiscard]] std::size_t buffered_bytes() const noexcept { return buffer_.size(); }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  void reset();
  /// Discards a started frame whose declared length is unacceptable.
  void reset_after_violation();

 private:
  [[nodiscard]] Status fail(ErrorCode code, std::string detail);

  Limits limits_{};
  std::deque<std::byte> buffer_{};
  bool failed_{false};
};

// --- payload codecs ---------------------------------------------------------

struct HelloPayload {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  AuthorityScopeMask requested_scopes{0};
  std::string client_name{};
};

struct HelloAckPayload {
  CoordinatorEpoch epoch{};
  SessionId session{};
  AuthorityScopeMask granted_scopes{0};
  std::uint16_t protocol_version{kProtocolVersionValue};
  bool accepted{false};
};

struct PublishConstraintSetPayload {
  ConstraintSet set{};
};

struct PublishConstraintSetAckPayload {
  ConstraintSetId set_id{};
  ConstraintSetGeneration generation{};
  Digest256 digest{};
};

struct EvaluateCandidatesPayload {
  ConstraintSetId set_id{};
  ConstraintSetGeneration expected_generation{};
  std::vector<CandidatePath> candidates{};
};

struct EvaluateCandidatesAckPayload {
  EvaluationBatch batch{};
};

struct ErrorReportPayload {
  ErrorCode code{ErrorCode::Ok};
  ReasonCode reason{ReasonCode::None};
  std::string detail{};
};

void encode_hello(ByteWriter& writer, const HelloPayload& payload);
[[nodiscard]] bool decode_hello(ByteReader& reader, const Limits& limits, HelloPayload& out);
void encode_hello_ack(ByteWriter& writer, const HelloAckPayload& payload);
[[nodiscard]] bool decode_hello_ack(ByteReader& reader, HelloAckPayload& out);
void encode_evaluate_request(ByteWriter& writer, const EvaluateCandidatesPayload& payload);
[[nodiscard]] bool decode_evaluate_request(ByteReader& reader, const Limits& limits,
                                           EvaluateCandidatesPayload& out);
void encode_evaluate_response(ByteWriter& writer, const EvaluateCandidatesAckPayload& payload);
[[nodiscard]] bool decode_evaluate_response(ByteReader& reader, const Limits& limits,
                                            EvaluateCandidatesAckPayload& out);
void encode_error_report(ByteWriter& writer, const ErrorReportPayload& payload);
[[nodiscard]] bool decode_error_report(ByteReader& reader, const Limits& limits, ErrorReportPayload& out);
void encode_publish_ack(ByteWriter& writer, const PublishConstraintSetAckPayload& payload);
[[nodiscard]] bool decode_publish_ack(ByteReader& reader, PublishConstraintSetAckPayload& out);

void encode_evaluation_batch(ByteWriter& writer, const EvaluationBatch& batch);
[[nodiscard]] bool decode_evaluation_batch(ByteReader& reader, const Limits& limits, EvaluationBatch& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_PROTOCOL_HPP
