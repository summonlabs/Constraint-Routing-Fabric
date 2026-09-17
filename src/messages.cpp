// Constraint Routing Fabric -- report payload codecs.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/messages.hpp"

#include <array>
#include <string>

namespace crf {
namespace {

void write_evidence(ByteWriter& writer, const EvidenceRequirements& evidence) {
  writer.put_u64(evidence.topology.value());
  writer.put_u64(evidence.link_state.value());
  writer.put_u64(evidence.capability.value());
  writer.put_u64(evidence.failure_domain.value());
  writer.put_u64(evidence.policy.value());
  writer.put_u64(evidence.planner.value());
  writer.put_u64(evidence.path_authority.value());
  writer.put_u64(evidence.max_evidence_age_ticks);
}

template <class Tag>
[[nodiscard]] bool read_generation_field(ByteReader& reader, Generation<Tag>& out) {
  std::uint64_t raw = 0;
  if (!reader.u64(raw)) {
    return false;
  }
  if (raw == 0) {
    out = Generation<Tag>{};
    return true;
  }
  if (!Generation<Tag>::is_representable(raw)) {
    reader.fail();
    return false;
  }
  out = Generation<Tag>::from_value(raw);
  return true;
}

[[nodiscard]] bool read_evidence(ByteReader& reader, EvidenceRequirements& out) {
  return read_generation_field(reader, out.topology) &&
         read_generation_field(reader, out.link_state) &&
         read_generation_field(reader, out.capability) &&
         read_generation_field(reader, out.failure_domain) &&
         read_generation_field(reader, out.policy) && read_generation_field(reader, out.planner) &&
         read_generation_field(reader, out.path_authority) &&
         reader.u64(out.max_evidence_age_ticks);
}

}  // namespace

void encode_definitions_report(ByteWriter& writer, const DefinitionsReportPayload& payload) {
  writer.put_bool(payload.found);
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  if (payload.found) {
    encode_definitions_snapshot(writer, payload.snapshot);
  }
}

bool decode_definitions_report(ByteReader& reader, const Limits& limits,
                               DefinitionsReportPayload& out) {
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.boolean(out.found) || !reader.u8(padding8) || !reader.u16(padding16) ||
      !reader.u32(padding32)) {
    return false;
  }
  if (padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  if (!out.found) {
    return true;
  }
  return decode_definitions_snapshot(reader, limits, out.snapshot);
}

void encode_results_report(ByteWriter& writer, const ResultsReportPayload& payload) {
  writer.put_bool(payload.found);
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  if (payload.found) {
    encode_results_snapshot(writer, payload.snapshot);
  }
}

bool decode_results_report(ByteReader& reader, const Limits& limits, ResultsReportPayload& out) {
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.boolean(out.found) || !reader.u8(padding8) || !reader.u16(padding16) ||
      !reader.u32(padding32)) {
    return false;
  }
  if (padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  if (!out.found) {
    return true;
  }
  return decode_results_snapshot(reader, limits, out.snapshot);
}

void encode_currentness_report(ByteWriter& writer, const CurrentnessReportPayload& payload) {
  writer.put_bool(payload.found);
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  if (!payload.found) {
    return;
  }
  const CurrentnessReport& report = payload.report;
  writer.put_u64(report.set_id.value());
  writer.put_u64(report.set_generation.value());
  writer.put_u8(static_cast<std::uint8_t>(report.state));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u64(report.evaluation_generation.value());
  write_evidence(writer, report.required_evidence);
  write_evidence(writer, report.published_evidence);
  writer.put_u64(static_cast<std::uint64_t>(report.current_results));
  writer.put_u64(static_cast<std::uint64_t>(report.revalidation_required));
  writer.put_u64(static_cast<std::uint64_t>(report.recovered_unproven));
  writer.put_bool(report.publisher_authority_live);
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(static_cast<std::uint32_t>(report.causes.size()));
  for (const CurrentnessCause cause : report.causes) {
    writer.put_u8(static_cast<std::uint8_t>(cause));
    writer.put_u8(0);
    writer.put_u16(0);
    writer.put_u32(0);
  }
}

bool decode_currentness_report(ByteReader& reader, const Limits& limits,
                               CurrentnessReportPayload& out) {
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.boolean(out.found) || !reader.u8(padding8) || !reader.u16(padding16) ||
      !reader.u32(padding32)) {
    return false;
  }
  if (padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  if (!out.found) {
    return true;
  }
  CurrentnessReport& report = out.report;
  std::uint64_t set_id = 0;
  std::uint64_t set_generation = 0;
  std::uint8_t state = 0;
  std::uint64_t counts[3] = {0, 0, 0};
  if (!reader.u64(set_id) || !reader.u64(set_generation) || !reader.u8(state) ||
      !reader.u8(padding8) || !reader.u16(padding16) || !reader.u32(padding32)) {
    return false;
  }
  if (padding8 != 0 || padding16 != 0 || padding32 != 0 || state == 0 || state > 7) {
    reader.fail();
    return false;
  }
  report.set_id = ConstraintSetId::from_value(set_id);
  if (set_generation != 0) {
    if (!ConstraintSetGeneration::is_representable(set_generation)) {
      reader.fail();
      return false;
    }
    report.set_generation = ConstraintSetGeneration::from_value(set_generation);
  }
  report.state = static_cast<ConstraintSetState>(state);
  if (!read_generation_field(reader, report.evaluation_generation) ||
      !read_evidence(reader, report.required_evidence) ||
      !read_evidence(reader, report.published_evidence)) {
    return false;
  }
  for (std::uint64_t& count : counts) {
    if (!reader.u64(count)) {
      return false;
    }
  }
  report.current_results = static_cast<std::size_t>(counts[0]);
  report.revalidation_required = static_cast<std::size_t>(counts[1]);
  report.recovered_unproven = static_cast<std::size_t>(counts[2]);
  if (!reader.boolean(report.publisher_authority_live) || !reader.u8(padding8) ||
      !reader.u16(padding16)) {
    return false;
  }
  std::uint32_t cause_count = 0;
  if (!reader.bounded_length(64, cause_count)) {
    return false;
  }
  report.causes.clear();
  report.causes.reserve(cause_count);
  for (std::uint32_t index = 0; index < cause_count; ++index) {
    std::uint8_t cause = 0;
    if (!reader.u8(cause) || !reader.u8(padding8) || !reader.u16(padding16) ||
        !reader.u32(padding32)) {
      return false;
    }
    if (cause == 0 || cause > 15 || padding8 != 0 || padding16 != 0 || padding32 != 0) {
      reader.fail();
      return false;
    }
    report.causes.push_back(static_cast<CurrentnessCause>(cause));
  }
  (void)limits;
  return reader.ok();
}

void encode_lifecycle_request(ByteWriter& writer, const LifecycleRequestPayload& payload) {
  writer.put_u64(payload.set_id.value());
  writer.put_u8(static_cast<std::uint8_t>(payload.event));
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
}

bool decode_lifecycle_request(ByteReader& reader, LifecycleRequestPayload& out) {
  std::uint64_t set_id = 0;
  std::uint8_t event = 0;
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.u64(set_id) || !reader.u8(event) || !reader.u8(padding8) || !reader.u16(padding16) ||
      !reader.u32(padding32)) {
    return false;
  }
  if (set_id == 0 || event == 0 || event > 9 || padding8 != 0 || padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  out.set_id = ConstraintSetId::from_value(set_id);
  out.event = static_cast<LifecycleEvent>(event);
  return true;
}

void encode_session_fenced(ByteWriter& writer, const SessionFencedPayload& payload) {
  writer.put_u64(payload.boot.value());
  writer.put_u64(payload.epoch.value());
}

bool decode_session_fenced(ByteReader& reader, SessionFencedPayload& out) {
  std::uint64_t boot = 0;
  std::uint64_t epoch = 0;
  if (!reader.u64(boot) || !reader.u64(epoch)) {
    return false;
  }
  if (boot == 0 || epoch == 0 || !CoordinatorEpoch::is_representable(epoch)) {
    reader.fail();
    return false;
  }
  out.boot = WorkerBootId::from_value(boot);
  out.epoch = CoordinatorEpoch::from_value(epoch);
  return true;
}

}  // namespace crf
