// Constraint Routing Fabric -- versioned durable state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/persistence.hpp"

#include <array>
#include <cstring>
#include <filesystem>
#include <set>
#include <span>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "constraint_routing_fabric/version.hpp"

namespace crf {
namespace {

constexpr std::size_t kMagicSize = 8;
constexpr std::size_t kHeaderSize = kMagicSize + 4 + 8;
constexpr std::size_t kTrailerSize = 4 + Digest256::kSize;
constexpr std::size_t kEnvelopeOverhead = kHeaderSize + kTrailerSize;

#if defined(_WIN32)
[[nodiscard]] std::wstring to_wide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return std::wstring();
  }
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), needed);
  return wide;
}

/// Writes bytes, flushes to stable storage and atomically replaces the target.
[[nodiscard]] Status atomic_write(const std::string& path, std::span<const std::byte> data) {
  const std::wstring wide_path = to_wide(path);
  if (wide_path.empty()) {
    return Status::failure(ErrorCode::InvalidArgument, "durable store path is not valid UTF-8");
  }
  std::wstring temporary = wide_path + L".tmp";
  HANDLE handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot create the temporary store file");
  }
  std::size_t written = 0;
  while (written < data.size()) {
    const DWORD chunk = static_cast<DWORD>(
        (data.size() - written) > 0x10000000u ? 0x10000000u : (data.size() - written));
    DWORD produced = 0;
    if (WriteFile(handle, data.data() + written, chunk, &produced, nullptr) == 0 || produced == 0) {
      CloseHandle(handle);
      DeleteFileW(temporary.c_str());
      return Status::failure(ErrorCode::DurableWriteFailed, "cannot write the temporary store file");
    }
    written += produced;
  }
  if (FlushFileBuffers(handle) == 0) {
    CloseHandle(handle);
    DeleteFileW(temporary.c_str());
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot flush the temporary store file");
  }
  CloseHandle(handle);
  if (MoveFileExW(temporary.c_str(), wide_path.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    DeleteFileW(temporary.c_str());
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot atomically replace the store file");
  }
  return Status::success();
}

[[nodiscard]] bool read_file(const std::string& path, std::vector<std::byte>& out, bool& exists) {
  const std::wstring wide_path = to_wide(path);
  HANDLE handle = CreateFileW(wide_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    exists = GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND;
    return false;
  }
  exists = true;
  LARGE_INTEGER size{};
  if (GetFileSizeEx(handle, &size) == 0 || size.QuadPart < 0) {
    CloseHandle(handle);
    return false;
  }
  out.assign(static_cast<std::size_t>(size.QuadPart), std::byte{0});
  std::size_t read = 0;
  while (read < out.size()) {
    const DWORD chunk = static_cast<DWORD>(
        (out.size() - read) > 0x10000000u ? 0x10000000u : (out.size() - read));
    DWORD produced = 0;
    if (ReadFile(handle, out.data() + read, chunk, &produced, nullptr) == 0) {
      CloseHandle(handle);
      return false;
    }
    if (produced == 0) {
      break;
    }
    read += produced;
  }
  CloseHandle(handle);
  out.resize(read);
  return true;
}
#else
[[nodiscard]] Status atomic_write(const std::string& path, std::span<const std::byte> data) {
  const std::string temporary = path + ".tmp";
  const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot create the temporary store file");
  }
  std::size_t written = 0;
  while (written < data.size()) {
    const ssize_t produced = ::write(fd, data.data() + written, data.size() - written);
    if (produced <= 0) {
      ::close(fd);
      ::unlink(temporary.c_str());
      return Status::failure(ErrorCode::DurableWriteFailed, "cannot write the temporary store file");
    }
    written += static_cast<std::size_t>(produced);
  }
  if (::fsync(fd) != 0) {
    ::close(fd);
    ::unlink(temporary.c_str());
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot flush the temporary store file");
  }
  ::close(fd);
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    ::unlink(temporary.c_str());
    return Status::failure(ErrorCode::DurableWriteFailed, "cannot atomically replace the store file");
  }
  return Status::success();
}

[[nodiscard]] bool read_file(const std::string& path, std::vector<std::byte>& out, bool& exists) {
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    exists = false;
    return false;
  }
  exists = true;
  out.clear();
  std::array<std::byte, 65536> buffer{};
  for (;;) {
    const ssize_t produced = ::read(fd, buffer.data(), buffer.size());
    if (produced < 0) {
      ::close(fd);
      return false;
    }
    if (produced == 0) {
      break;
    }
    out.insert(out.end(), buffer.begin(), buffer.begin() + produced);
  }
  ::close(fd);
  return true;
}
#endif

}  // namespace

std::vector<std::byte> encode_envelope(std::span<const std::byte> payload) {
  ByteWriter writer;
  for (std::size_t index = 0; index < kMagicSize; ++index) {
    writer.put_u8(static_cast<std::uint8_t>(kStoreMagic[index]));
  }
  writer.put_u32(kPersistenceFormatVersion);
  writer.put_u64(static_cast<std::uint64_t>(payload.size()));
  writer.put_raw(payload);
  const std::uint32_t checksum = crc32c(payload);
  writer.put_u32(checksum);
  Sha256 sha;
  sha.update(payload);
  const Digest256 digest = sha.finish();
  writer.put_raw(std::span<const std::byte>(digest.data(), Digest256::kSize));
  return writer.buffer();
}

Status decode_envelope(std::span<const std::byte> raw, const Limits& limits,
                       std::vector<std::byte>& payload) {
  if (raw.size() < kEnvelopeOverhead) {
    return Status::failure(ErrorCode::Truncated, "durable envelope is shorter than its header");
  }
  for (std::size_t index = 0; index < kMagicSize; ++index) {
    if (std::to_integer<std::uint8_t>(raw[index]) !=
        static_cast<std::uint8_t>(kStoreMagic[index])) {
      return Status::failure(ErrorCode::PersistenceCorrupt, "durable envelope magic does not match");
    }
  }
  ByteReader reader(raw.subspan(kMagicSize));
  std::uint32_t version = 0;
  std::uint64_t payload_length = 0;
  if (!reader.u32(version) || !reader.u64(payload_length)) {
    return Status::failure(ErrorCode::Truncated, "durable envelope header is truncated");
  }
  if (version != kPersistenceFormatVersion) {
    return Status::failure(ErrorCode::UnsupportedVersion, "durable envelope version is not supported");
  }
  if (payload_length > limits.max_persistence_record_bytes) {
    return Status::failure(ErrorCode::ResourceLimit, "durable envelope declares an absurd payload size");
  }
  const std::uint64_t expected_total = static_cast<std::uint64_t>(kEnvelopeOverhead) + payload_length;
  if (raw.size() != expected_total) {
    return Status::failure(raw.size() < expected_total ? ErrorCode::Truncated : ErrorCode::TrailingBytes,
                           "durable envelope length does not match its declared payload");
  }
  const std::span<const std::byte> body = raw.subspan(kHeaderSize, static_cast<std::size_t>(payload_length));
  const std::span<const std::byte> trailer = raw.subspan(kHeaderSize + static_cast<std::size_t>(payload_length));
  if (crc32c(body) != [&trailer] {
        std::uint32_t value = 0;
        for (std::size_t index = 0; index < 4; ++index) {
          value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(trailer[index]))
                   << (index * 8);
        }
        return value;
      }()) {
    return Status::failure(ErrorCode::IntegrityMismatch, "durable envelope checksum does not match");
  }
  Sha256 sha;
  sha.update(body);
  const Digest256 digest = sha.finish();
  for (std::size_t index = 0; index < Digest256::kSize; ++index) {
    if (std::to_integer<std::uint8_t>(trailer[4 + index]) !=
        std::to_integer<std::uint8_t>(digest.data()[index])) {
      return Status::failure(ErrorCode::IntegrityMismatch, "durable envelope digest does not match");
    }
  }
  payload.assign(body.begin(), body.end());
  return Status::success();
}

void encode_persistent_state(ByteWriter& writer, const PersistentState& state) {
  writer.put_u64(state.epoch.value());
  writer.put_bool(state.initialized);
  writer.put_u8(0);
  writer.put_u16(0);
  writer.put_u32(0);
  writer.put_u64(state.evidence.topology.value());
  writer.put_u64(state.evidence.link_state.value());
  writer.put_u64(state.evidence.capability.value());
  writer.put_u64(state.evidence.failure_domain.value());
  writer.put_u64(state.evidence.policy.value());
  writer.put_u64(state.evidence.planner.value());
  writer.put_u64(state.evidence.path_authority.value());
  writer.put_u64(state.evidence.max_evidence_age_ticks);
  writer.put_u64(state.last_evaluation_generation.value());
  encode_watermarks(writer, state.watermarks);
  writer.put_u32(static_cast<std::uint32_t>(state.sets.size()));
  for (const ConstraintSet& set : state.sets) {
    encode_constraint_set(writer, set);
  }
  writer.put_u32(static_cast<std::uint32_t>(state.evaluations.size()));
  for (const EvaluationRecord& record : state.evaluations) {
    encode_evaluation(writer, record);
  }
  writer.put_u32(static_cast<std::uint32_t>(state.populations.size()));
  for (const CandidatePopulation& population : state.populations) {
    writer.put_u64(population.set_id.value());
    writer.put_u32(static_cast<std::uint32_t>(population.candidates.size()));
    for (const CandidatePath& candidate : population.candidates) {
      encode_candidate(writer, candidate);
    }
  }
  writer.put_u32(static_cast<std::uint32_t>(state.live_boots.size()));
  for (const WorkerBootId& boot : state.live_boots) {
    writer.put_u64(boot.value());
  }
  writer.put_u32(static_cast<std::uint32_t>(state.fenced_boots.size()));
  for (const FencedBootRecord& record : state.fenced_boots) {
    encode_fenced_boot(writer, record);
  }
  writer.put_u32(static_cast<std::uint32_t>(state.attempts.size()));
  for (const MutationAttemptRecord& record : state.attempts) {
    encode_mutation_attempt(writer, record);
  }
}

namespace {

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

}  // namespace

bool decode_persistent_state(ByteReader& reader, const Limits& limits, PersistentState& out) {
  constexpr std::uint32_t max_populations = 64;
  std::uint64_t epoch = 0;
  std::uint8_t padding8 = 0;
  std::uint16_t padding16 = 0;
  std::uint32_t padding32 = 0;
  if (!reader.u64(epoch) || !reader.boolean(out.initialized) || !reader.u8(padding8) ||
      !reader.u16(padding16) || !reader.u32(padding32)) {
    return false;
  }
  if ((epoch != 0 && !CoordinatorEpoch::is_representable(epoch)) || padding8 != 0 ||
      padding16 != 0 || padding32 != 0) {
    reader.fail();
    return false;
  }
  out.epoch = epoch == 0 ? CoordinatorEpoch{} : CoordinatorEpoch::from_value(epoch);
  if (!read_generation_field(reader, out.evidence.topology) ||
      !read_generation_field(reader, out.evidence.link_state) ||
      !read_generation_field(reader, out.evidence.capability) ||
      !read_generation_field(reader, out.evidence.failure_domain) ||
      !read_generation_field(reader, out.evidence.policy) ||
      !read_generation_field(reader, out.evidence.planner) ||
      !read_generation_field(reader, out.evidence.path_authority) ||
      !reader.u64(out.evidence.max_evidence_age_ticks) ||
      !read_generation_field(reader, out.last_evaluation_generation)) {
    return false;
  }
  if (!decode_watermarks(reader, limits, out.watermarks)) {
    return false;
  }
  std::uint32_t count = 0;
  if (!reader.bounded_length(limits.max_constraint_sets, count)) {
    return false;
  }
  out.sets.clear();
  out.sets.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    ConstraintSet set;
    if (!decode_constraint_set(reader, limits, set)) {
      return false;
    }
    out.sets.push_back(std::move(set));
  }
  if (!reader.bounded_length(limits.max_evaluations_retained, count)) {
    return false;
  }
  out.evaluations.clear();
  out.evaluations.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    EvaluationRecord record;
    if (!decode_evaluation(reader, limits, record)) {
      return false;
    }
    out.evaluations.push_back(std::move(record));
  }
  if (!reader.bounded_length(max_populations, count)) {
    return false;
  }
  out.populations.clear();
  out.populations.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    CandidatePopulation population;
    std::uint64_t set_id = 0;
    std::uint32_t candidates = 0;
    if (!reader.u64(set_id) || set_id == 0) {
      reader.fail();
      return false;
    }
    population.set_id = ConstraintSetId::from_value(set_id);
    if (!reader.bounded_length(limits.max_candidates_per_evaluation, candidates)) {
      return false;
    }
    population.candidates.reserve(candidates);
    for (std::uint32_t item = 0; item < candidates; ++item) {
      CandidatePath candidate;
      if (!decode_candidate(reader, limits, candidate)) {
        return false;
      }
      population.candidates.push_back(std::move(candidate));
    }
    out.populations.push_back(std::move(population));
  }
  if (!reader.bounded_length(limits.max_fenced_boots, count)) {
    return false;
  }
  out.live_boots.clear();
  out.live_boots.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint64_t boot = 0;
    if (!reader.u64(boot)) {
      return false;
    }
    if (boot == 0) {
      reader.fail();
      return false;
    }
    out.live_boots.push_back(WorkerBootId::from_value(boot));
  }
  if (!reader.bounded_length(limits.max_fenced_boots, count)) {
    return false;
  }
  out.fenced_boots.clear();
  out.fenced_boots.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    FencedBootRecord record;
    if (!decode_fenced_boot(reader, record)) {
      return false;
    }
    out.fenced_boots.push_back(record);
  }
  if (!reader.bounded_length(limits.max_mutation_attempts, count)) {
    return false;
  }
  out.attempts.clear();
  out.attempts.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    MutationAttemptRecord record;
    if (!decode_mutation_attempt(reader, record)) {
      return false;
    }
    out.attempts.push_back(record);
  }
  if (!reader.ok() || !reader.at_end()) {
    return false;
  }
  return true;
}

Status validate_persistent_state(const PersistentState& state, const Limits& limits) {
  std::string why;
  if (!validate_limits(limits, why)) {
    return Status::failure(ErrorCode::InvalidArgument, why);
  }
  if (state.epoch.is_valid() && !CoordinatorEpoch::is_representable(state.epoch.value())) {
    return Status::failure(ErrorCode::ImpossibleGeneration, "persisted coordinator epoch is impossible");
  }
  if (state.sets.size() > limits.max_constraint_sets) {
    return Status::failure(ErrorCode::ResourceLimit, "persisted constraint set count exceeds the limit");
  }
  if (state.evaluations.size() > limits.max_evaluations_retained) {
    return Status::failure(ErrorCode::ResourceLimit, "persisted evaluation count exceeds the limit");
  }
  if (state.fenced_boots.size() > limits.max_fenced_boots) {
    return Status::failure(ErrorCode::ResourceLimit, "persisted fenced boot count exceeds the limit");
  }
  if (state.attempts.size() > limits.max_mutation_attempts) {
    return Status::failure(ErrorCode::ResourceLimit, "persisted mutation attempt count exceeds the limit");
  }

  std::set<ConstraintSetId> set_ids;
  for (const ConstraintSet& set : state.sets) {
    if (!set_ids.insert(set.id).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted constraint set identity");
    }
    const Status status = verify_canonical_constraint_set(set, limits);
    if (!status.ok()) {
      return Status::failure(status.code(), std::string("persisted constraint set is invalid: ") + status.detail());
    }
  }

  std::set<ConstraintSetId> population_sets;
  for (const CandidatePopulation& population : state.populations) {
    if (set_ids.find(population.set_id) == set_ids.end()) {
      return Status::failure(ErrorCode::NotFound,
                             "persisted candidate population binds a constraint set that is not present");
    }
    if (!population_sets.insert(population.set_id).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted candidate population");
    }
    if (population.candidates.size() > limits.max_candidates_per_evaluation) {
      return Status::failure(ErrorCode::ResourceLimit, "persisted candidate population exceeds the limit");
    }
    for (const CandidatePath& candidate : population.candidates) {
      const Status status = validate_candidate(candidate, limits);
      if (!status.ok()) {
        return Status::failure(status.code(),
                               std::string("persisted candidate is invalid: ") + status.detail());
      }
    }
  }

  std::set<ConstraintEvaluationId> evaluation_ids;
  std::set<std::pair<std::uint64_t, std::uint64_t>> current_results;
  EvaluationGeneration highest;
  for (const EvaluationRecord& record : state.evaluations) {
    if (!evaluation_ids.insert(record.id).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted evaluation identity");
    }
    if (!record.set_id.is_valid() || !record.path.is_valid() ||
        !record.authority_generation.is_valid() || !record.generation.is_valid()) {
      return Status::failure(ErrorCode::ImpossibleGeneration,
                             "persisted evaluation carries an impossible identity or generation");
    }
    if (set_ids.find(record.set_id) == set_ids.end()) {
      return Status::failure(ErrorCode::NotFound,
                             "persisted evaluation binds a constraint set that is not present");
    }
    if (highest < record.generation) {
      highest = record.generation;
    }
    // Reason vectors must be canonical and strictly ascending.
    for (std::size_t index = 0; index < record.reasons.size(); ++index) {
      if (reason_class_of(record.reasons[index].code) != record.reasons[index].reason_class) {
        return Status::failure(ErrorCode::Malformed, "persisted reason class disagrees with its code");
      }
      if (index > 0 && !reason_less(record.reasons[index - 1], record.reasons[index])) {
        return Status::failure(ErrorCode::Malformed, "persisted reason vector is not canonical");
      }
    }
    if (record.reasons.empty()) {
      if (record.primary_reason != ReasonCode::None) {
        return Status::failure(ErrorCode::Malformed,
                               "persisted evaluation with no reasons declares a primary reason");
      }
    } else if (record.primary_reason != record.reasons.front().code) {
      return Status::failure(ErrorCode::Malformed,
                             "persisted primary reason is not the head of the reason vector");
    }
    if (record.reasons.size() > limits.max_explanation_reasons) {
      return Status::failure(ErrorCode::ResourceLimit, "persisted reason vector exceeds the limit");
    }
    if (record.state == ResultState::Current) {
      const auto key = std::make_pair(record.set_id.value(), record.path.value());
      if (!current_results.insert(key).second) {
        return Status::failure(ErrorCode::DuplicateIdentity,
                               "two current results for the same constraint set and path");
      }
    }
    const std::array<EvidenceFamily, 7> families = {
        EvidenceFamily::Topology,      EvidenceFamily::LinkState,     EvidenceFamily::Capability,
        EvidenceFamily::FailureDomain, EvidenceFamily::Policy,        EvidenceFamily::Planner,
        EvidenceFamily::PathAuthority};
    for (const EvidenceFamily family : families) {
      if ((record.consulted & family_bit(family)) == 0) {
        continue;
      }
      const std::uint64_t required = [&record, family] {
        switch (family) {
          case EvidenceFamily::Topology: return record.evidence.topology.value();
          case EvidenceFamily::LinkState: return record.evidence.link_state.value();
          case EvidenceFamily::Capability: return record.evidence.capability.value();
          case EvidenceFamily::FailureDomain: return record.evidence.failure_domain.value();
          case EvidenceFamily::Policy: return record.evidence.policy.value();
          case EvidenceFamily::Planner: return record.evidence.planner.value();
          case EvidenceFamily::PathAuthority: return record.evidence.path_authority.value();
          default: return std::uint64_t{0};
        }
      }();
      if (required == 0) {
        return Status::failure(ErrorCode::Malformed,
                               "persisted evaluation consults a family it did not bind");
      }
    }
  }
  if (!state.evaluations.empty()) {
    if (!state.last_evaluation_generation.is_valid() ||
        state.last_evaluation_generation < highest) {
      return Status::failure(ErrorCode::ImpossibleGeneration,
                             "persisted evaluation generation counter is behind its records");
    }
  }

  if (state.live_boots.size() > limits.max_fenced_boots) {
    return Status::failure(ErrorCode::ResourceLimit, "persisted live boot count exceeds the limit");
  }
  std::set<WorkerBootId> live;
  for (const WorkerBootId& boot : state.live_boots) {
    if (!boot.is_valid()) {
      return Status::failure(ErrorCode::InvalidArgument, "persisted live boot identity is zero");
    }
    if (!live.insert(boot).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted live boot");
    }
  }

  std::set<WorkerBootId> boots;
  for (const FencedBootRecord& record : state.fenced_boots) {
    if (!record.boot.is_valid()) {
      return Status::failure(ErrorCode::InvalidArgument, "persisted fenced boot identity is zero");
    }
    if (!boots.insert(record.boot).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted fenced boot");
    }
  }
  std::set<MutationAttemptId> attempts;
  for (const MutationAttemptRecord& record : state.attempts) {
    if (!record.attempt.is_valid()) {
      return Status::failure(ErrorCode::InvalidArgument, "persisted mutation attempt identity is zero");
    }
    if (!attempts.insert(record.attempt).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "duplicate persisted mutation attempt");
    }
  }
  return Status::success();
}

Digest256 persistent_state_digest(const PersistentState& state) {
  ByteWriter writer;
  encode_persistent_state(writer, state);
  SemanticHasher hasher;
  hasher.begin("crf.persistent-state.v1");
  hasher.put_bytes(writer.span());
  return hasher.finish();
}

namespace {

/// Takes exclusive ownership of the store path. Returns an open handle (or the
/// equivalent) that the caller must release, or an error status.
[[nodiscard]] Result<std::uintptr_t> acquire_store_lock(const std::string& path) {
#if defined(_WIN32)
  const std::wstring wide = to_wide(path + ".lock");
  if (wide.empty()) {
    return Result<std::uintptr_t>::failure(ErrorCode::InvalidArgument,
                                           "durable store path is not valid UTF-8");
  }
  // Sharing is disabled: a second open of the same store fails while the first
  // owner is alive, and the operating system releases the handle on process exit.
  HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Result<std::uintptr_t>::failure(
        ErrorCode::PersistenceUnavailable,
        "durable store is already owned by another open coordinator");
  }
  return Result<std::uintptr_t>::success(reinterpret_cast<std::uintptr_t>(handle));
#else
  const std::string lock_path = path + ".lock";
  const int descriptor = ::open(lock_path.c_str(), O_RDWR | O_CREAT, 0644);
  if (descriptor < 0) {
    return Result<std::uintptr_t>::failure(ErrorCode::PersistenceUnavailable,
                                           "cannot open the durable store lock file");
  }
  struct flock lock {};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  if (::fcntl(descriptor, F_SETLK, &lock) != 0) {
    ::close(descriptor);
    return Result<std::uintptr_t>::failure(
        ErrorCode::PersistenceUnavailable,
        "durable store is already owned by another open coordinator");
  }
  return Result<std::uintptr_t>::success(static_cast<std::uintptr_t>(descriptor));
#endif
}

void release_store_lock(std::uintptr_t handle) noexcept {
  if (handle == ~std::uintptr_t{0}) {
    return;
  }
#if defined(_WIN32)
  (void)CloseHandle(reinterpret_cast<HANDLE>(handle));
#else
  (void)::close(static_cast<int>(handle));
#endif
}

}  // namespace

DurableStore::DurableStore(std::string path, Limits limits)
    : path_(std::move(path)), limits_(limits) {}

DurableStore::~DurableStore() { release_store_lock(lock_handle_); }

Result<std::unique_ptr<DurableStore>> DurableStore::open(const std::string& path, const Limits& limits,
                                                         bool allow_initialize) {
  std::string why;
  if (!validate_limits(limits, why)) {
    return Result<std::unique_ptr<DurableStore>>::failure(ErrorCode::InvalidArgument, why);
  }
  if (path.empty()) {
    return Result<std::unique_ptr<DurableStore>>::failure(ErrorCode::InvalidArgument,
                                                          "durable store path is empty");
  }
  auto store = std::unique_ptr<DurableStore>(new DurableStore(path, limits));
  const Result<std::uintptr_t> lock = acquire_store_lock(path);
  if (!lock.ok()) {
    return Result<std::unique_ptr<DurableStore>>::failure(lock.code(), lock.detail());
  }
  store->lock_handle_ = lock.value();

  // A store that exists but does not describe a valid state is quarantined, not
  // silently replaced: the unreadable bytes are preserved for inspection.
  const Result<PersistentState> existing = store->load();
  if (existing.ok() || existing.code() == ErrorCode::NotFound) {
    return Result<std::unique_ptr<DurableStore>>::success(std::move(store));
  }
  if (!allow_initialize) {
    return Result<std::unique_ptr<DurableStore>>::failure(
        existing.code(),
        std::string("durable store exists but is not usable: ") + existing.detail());
  }
  // Conservative recovery: the unreadable file is preserved, never discarded.
  std::error_code error;
  for (int attempt = 1; attempt <= 64; ++attempt) {
    const std::string quarantine = path + ".quarantine-" + std::to_string(attempt);
    if (!std::filesystem::exists(quarantine, error)) {
      std::filesystem::rename(path, quarantine, error);
      break;
    }
  }
  return Result<std::unique_ptr<DurableStore>>::success(std::move(store));
}

Status DurableStore::save(const PersistentState& state) {
  const Status valid = validate_persistent_state(state, limits_);
  if (!valid.ok()) {
    return valid;
  }
  ByteWriter writer;
  encode_persistent_state(writer, state);
  if (writer.size() > limits_.max_persistence_record_bytes) {
    ++failures_;
    return Status::failure(ErrorCode::ResourceLimit, "persistent state exceeds the record size limit");
  }
  const std::vector<std::byte> envelope = encode_envelope(writer.span());
  const Status written = atomic_write(path_, envelope);
  if (!written.ok()) {
    ++failures_;
    return written;
  }
  ++writes_;
  return Status::success();
}

Result<PersistentState> DurableStore::load() const {
  std::vector<std::byte> raw;
  bool exists = false;
  if (!read_file(path_, raw, exists)) {
    if (!exists) {
      return Result<PersistentState>::failure(ErrorCode::NotFound, "durable store file does not exist");
    }
    return Result<PersistentState>::failure(ErrorCode::PersistenceUnavailable,
                                            "durable store file could not be read");
  }
  std::vector<std::byte> payload;
  const Status decoded = decode_envelope(raw, limits_, payload);
  if (!decoded.ok()) {
    return Result<PersistentState>::failure(decoded.code(), decoded.detail());
  }
  ByteReader reader(payload);
  PersistentState state;
  if (!decode_persistent_state(reader, limits_, state)) {
    return Result<PersistentState>::failure(ErrorCode::PersistenceCorrupt,
                                            "durable state payload is malformed");
  }
  const Status valid = validate_persistent_state(state, limits_);
  if (!valid.ok()) {
    return Result<PersistentState>::failure(ErrorCode::PersistenceCorrupt, valid.detail());
  }
  return Result<PersistentState>::success(std::move(state));
}

bool DurableStore::exists() const {
  std::error_code error;
  return std::filesystem::exists(path_, error);
}

}  // namespace crf
