// Constraint Routing Fabric -- report payloads shared by the server and client.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_MESSAGES_HPP
#define CONSTRAINT_ROUTING_FABRIC_MESSAGES_HPP

#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/coordinator.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/snapshot.hpp"

namespace crf {

struct DefinitionsReportPayload {
  bool found{false};
  DefinitionsSnapshot snapshot{};
};

struct ResultsReportPayload {
  bool found{false};
  ResultsSnapshot snapshot{};
};

struct CurrentnessReportPayload {
  bool found{false};
  CurrentnessReport report{};
};

struct SessionFencedPayload {
  WorkerBootId boot{};
  CoordinatorEpoch epoch{};
};

struct LifecycleRequestPayload {
  ConstraintSetId set_id{};
  LifecycleEvent event{LifecycleEvent::Activate};
};

void encode_definitions_report(ByteWriter& writer, const DefinitionsReportPayload& payload);
[[nodiscard]] bool decode_definitions_report(ByteReader& reader, const Limits& limits,
                                             DefinitionsReportPayload& out);
void encode_results_report(ByteWriter& writer, const ResultsReportPayload& payload);
[[nodiscard]] bool decode_results_report(ByteReader& reader, const Limits& limits,
                                         ResultsReportPayload& out);
void encode_currentness_report(ByteWriter& writer, const CurrentnessReportPayload& payload);
[[nodiscard]] bool decode_currentness_report(ByteReader& reader, const Limits& limits,
                                             CurrentnessReportPayload& out);
void encode_lifecycle_request(ByteWriter& writer, const LifecycleRequestPayload& payload);
[[nodiscard]] bool decode_lifecycle_request(ByteReader& reader, LifecycleRequestPayload& out);
void encode_session_fenced(ByteWriter& writer, const SessionFencedPayload& payload);
[[nodiscard]] bool decode_session_fenced(ByteReader& reader, SessionFencedPayload& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_MESSAGES_HPP
