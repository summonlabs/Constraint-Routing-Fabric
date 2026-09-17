// Constraint Routing Fabric -- authority, epochs and fencing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/authority.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <random>
#include <string>

namespace crf {
namespace {

[[nodiscard]] std::string describe_scopes(AuthorityScopeMask mask) {
  std::string text;
  const std::array<AuthorityScope, 7> scopes = {
      AuthorityScope::PublishConstraintSet, AuthorityScope::PublishEvaluation,
      AuthorityScope::ApplyLifecycle,       AuthorityScope::ReadDefinitions,
      AuthorityScope::ReadResults,          AuthorityScope::RegisterPublisher,
      AuthorityScope::AdministerFencing};
  for (const AuthorityScope scope : scopes) {
    if (has_scope(mask, scope)) {
      if (!text.empty()) {
        text += "|";
      }
      text += to_string(scope);
    }
  }
  return text.empty() ? std::string("None") : text;
}

}  // namespace

const char* to_string(AuthorityScope scope) noexcept {
  switch (scope) {
    case AuthorityScope::None: return "None";
    case AuthorityScope::PublishConstraintSet: return "PublishConstraintSet";
    case AuthorityScope::PublishEvaluation: return "PublishEvaluation";
    case AuthorityScope::ApplyLifecycle: return "ApplyLifecycle";
    case AuthorityScope::ReadDefinitions: return "ReadDefinitions";
    case AuthorityScope::ReadResults: return "ReadResults";
    case AuthorityScope::RegisterPublisher: return "RegisterPublisher";
    case AuthorityScope::AdministerFencing: return "AdministerFencing";
  }
  return "Unknown";
}

Status AuthorityRegistry::establish_epoch(CoordinatorEpoch epoch) {
  if (!epoch.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "coordinator epoch must be non-zero");
  }
  if (epoch_ .is_valid() && epoch <= epoch_) {
    return Status::failure(ErrorCode::EpochMismatch,
                           "coordinator epoch must advance strictly; equal or lower epochs are refused");
  }
  epoch_ = epoch;
  return Status::success();
}

Status AuthorityRegistry::register_publisher(const PublisherRegistration& registration,
                                             const Limits& limits) {
  if (!registration.publisher.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "publisher identity must be non-zero");
  }
  if (!registration.boot.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "worker boot identity must be non-zero");
  }
  if (!registration.session.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "session identity must be non-zero");
  }
  if (!registration.registered_at.is_valid() || registration.registered_at != epoch_) {
    return Status::failure(ErrorCode::EpochMismatch,
                           "publisher registration must bind the current coordinator epoch");
  }
  if (is_boot_fenced(registration.boot)) {
    return Status::failure(ErrorCode::Fenced,
                           "worker boot is permanently fenced and can never register again");
  }
  if (registration.scopes == 0) {
    return Status::failure(ErrorCode::Unauthorized,
                           "default deny: a registration without any scope authorizes nothing");
  }

  // A publisher that re-registers with a fresh boot fences its previous boot.
  // This is worker reincarnation: the old process can never publish again.
  for (PublisherRegistration& existing : registrations_) {
    if (existing.publisher == registration.publisher && existing.live) {
      if (existing.boot == registration.boot) {
        return Status::failure(ErrorCode::DuplicateIdentity,
                               "the same publisher and boot is already registered");
      }
      const Status fenced = fence_boot(existing.boot, epoch_, registration.registered_tick, limits);
      if (!fenced.ok()) {
        return fenced;
      }
      existing.live = false;
    }
  }

  std::size_t live = 0;
  for (const PublisherRegistration& existing : registrations_) {
    if (existing.live) {
      ++live;
    }
  }
  if (live >= limits.max_publishers) {
    return Status::failure(ErrorCode::ResourceLimit, "publisher limit reached");
  }
  std::set<SessionId> sessions;
  for (const PublisherRegistration& existing : registrations_) {
    if (existing.live) {
      sessions.insert(existing.session);
    }
  }
  if (sessions.count(registration.session) == 0 && sessions.size() >= limits.max_sessions) {
    return Status::failure(ErrorCode::ResourceLimit, "session limit reached");
  }

  registrations_.push_back(registration);
  return Status::success();
}

Status AuthorityRegistry::drop_session(SessionId session) {
  bool found = false;
  for (PublisherRegistration& registration : registrations_) {
    if (registration.live && registration.session == session) {
      registration.live = false;
      found = true;
    }
  }
  if (!found) {
    return Status::failure(ErrorCode::NotFound, "session is not live");
  }
  return Status::success();
}

bool AuthorityRegistry::boot_of_session(SessionId session, WorkerBootId& out) const noexcept {
  for (const PublisherRegistration& registration : registrations_) {
    if (registration.live && registration.session == session) {
      out = registration.boot;
      return true;
    }
  }
  return false;
}

Status AuthorityRegistry::fence_boot(WorkerBootId boot, CoordinatorEpoch at, std::uint64_t tick,
                                     const Limits& limits) {
  if (!boot.is_valid()) {
    return Status::failure(ErrorCode::InvalidArgument, "worker boot identity must be non-zero");
  }
  if (fenced_.find(boot) != fenced_.end()) {
    return Status::success();
  }
  if (fenced_.size() >= limits.max_fenced_boots) {
    return Status::failure(ErrorCode::ResourceLimit, "fenced boot registry is full");
  }
  FencedBootRecord record;
  record.boot = boot;
  record.fenced_at = at;
  record.fenced_tick = tick;
  fenced_.emplace(boot, record);
  for (PublisherRegistration& registration : registrations_) {
    if (registration.boot == boot) {
      registration.live = false;
    }
  }
  return Status::success();
}

bool AuthorityRegistry::is_boot_fenced(WorkerBootId boot) const noexcept {
  return fenced_.find(boot) != fenced_.end();
}

std::size_t AuthorityRegistry::live_publishers() const noexcept {
  std::size_t live = 0;
  for (const PublisherRegistration& registration : registrations_) {
    if (registration.live) {
      ++live;
    }
  }
  return live;
}

std::size_t AuthorityRegistry::live_sessions() const noexcept {
  std::set<SessionId> sessions;
  for (const PublisherRegistration& registration : registrations_) {
    if (registration.live) {
      sessions.insert(registration.session);
    }
  }
  return sessions.size();
}

Status AuthorityRegistry::authorize(const AuthorityContext& context,
                                    AuthorityScopeMask required) const {
  if (!context.epoch.is_valid() || !context.publisher.is_valid() || !context.worker_boot.is_valid() ||
      !context.attempt.is_valid() || !context.session.is_valid()) {
    return Status::failure(ErrorCode::Unauthorized,
                           "default deny: an incomplete authority context authorizes nothing");
  }
  if (!epoch_.is_valid() || context.epoch != epoch_) {
    return Status::failure(ErrorCode::EpochMismatch,
                           "authority context carries a stale or future coordinator epoch");
  }
  if (is_boot_fenced(context.worker_boot)) {
    return Status::failure(ErrorCode::Fenced, "worker boot is fenced");
  }
  for (const PublisherRegistration& registration : registrations_) {
    if (!registration.live || registration.publisher != context.publisher) {
      continue;
    }
    if (registration.session != context.session) {
      continue;
    }
    if (registration.boot != context.worker_boot) {
      return Status::failure(ErrorCode::Fenced,
                             "publisher is live under a different worker boot; this boot is stale");
    }
    if (required != 0 && (registration.scopes & required) != required) {
      return Status::failure(ErrorCode::Unauthorized,
                             std::string("scope not authorized; held scopes are ") +
                                 describe_scopes(registration.scopes));
    }
    return Status::success();
  }
  return Status::failure(ErrorCode::Unauthorized,
                         "default deny: publisher is not registered live in this session");
}

Result<ReplayVerdict> AuthorityRegistry::observe_attempt(MutationAttemptId attempt,
                                                         const Digest256& payload, std::uint64_t tick,
                                                         const Limits& limits) {
  if (!attempt.is_valid()) {
    return Result<ReplayVerdict>::failure(ErrorCode::InvalidArgument,
                                          "mutation attempt identity must be non-zero");
  }
  for (const MutationAttemptRecord& record : attempts_) {
    if (record.attempt == attempt) {
      if (record.payload == payload) {
        return Result<ReplayVerdict>::success(ReplayVerdict::ExactReplay);
      }
      return Result<ReplayVerdict>::success(ReplayVerdict::Conflict);
    }
  }
  MutationAttemptRecord record;
  record.attempt = attempt;
  record.payload = payload;
  record.recorded_tick = tick;
  if (attempts_.size() >= limits.max_mutation_attempts) {
    // The de-duplication window is bounded. The oldest attempt is evicted and
    // the window size is part of the documented contract.
    attempts_.erase(attempts_.begin());
  }
  attempts_.push_back(record);
  return Result<ReplayVerdict>::success(ReplayVerdict::Fresh);
}

void AuthorityRegistry::restore_durable_state(CoordinatorEpoch epoch,
                                              std::vector<FencedBootRecord> fenced) {
  epoch_ = epoch;
  fenced_.clear();
  for (const FencedBootRecord& record : fenced) {
    if (record.boot.is_valid()) {
      fenced_.emplace(record.boot, record);
    }
  }
  // Durable state is not live authority: no registration is restored.
  registrations_.clear();
  attempts_.clear();
}

WorkerBootId AuthorityRegistry::fresh_worker_boot() noexcept {
  static std::atomic<std::uint64_t> counter{0};
  static const std::uint64_t process_salt = [] {
    std::random_device device;
    const auto now = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::uint64_t salt = (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
    salt ^= now;
    return salt == 0 ? 0x9e3779b97f4a7c15ull : salt;
  }();
  const std::uint64_t sequence = counter.fetch_add(1) + 1;
  std::uint64_t value = process_salt ^ (sequence * 0x9e3779b97f4a7c15ull);
  if (value == 0) {
    value = 1;
  }
  return WorkerBootId::from_value(value);
}

void AuthorityRegistry::clear_live_authority() noexcept {
  registrations_.clear();
  attempts_.clear();
}

void encode_fenced_boot(ByteWriter& writer, const FencedBootRecord& record) {
  writer.put_u64(record.boot.value());
  writer.put_u64(record.fenced_at.value());
  writer.put_u64(record.fenced_tick);
}

bool decode_fenced_boot(ByteReader& reader, FencedBootRecord& out) {
  std::uint64_t boot = 0;
  std::uint64_t fenced_at = 0;
  std::uint64_t tick = 0;
  if (!reader.u64(boot) || !reader.u64(fenced_at) || !reader.u64(tick)) {
    return false;
  }
  if (boot == 0 || (fenced_at != 0 && !CoordinatorEpoch::is_representable(fenced_at))) {
    reader.fail();
    return false;
  }
  out.boot = WorkerBootId::from_value(boot);
  out.fenced_at = fenced_at == 0 ? CoordinatorEpoch{} : CoordinatorEpoch::from_value(fenced_at);
  out.fenced_tick = tick;
  return true;
}

void encode_mutation_attempt(ByteWriter& writer, const MutationAttemptRecord& record) {
  writer.put_u64(record.attempt.value());
  const std::span<const std::byte> digest(record.payload.data(), Digest256::kSize);
  writer.put_raw(digest);
  writer.put_u64(record.recorded_tick);
}

bool decode_mutation_attempt(ByteReader& reader, MutationAttemptRecord& out) {
  std::uint64_t attempt = 0;
  if (!reader.u64(attempt)) {
    return false;
  }
  std::array<std::byte, Digest256::kSize> digest_bytes{};
  if (!reader.raw(std::span<std::byte>(digest_bytes)) || !reader.u64(out.recorded_tick)) {
    return false;
  }
  if (attempt == 0) {
    reader.fail();
    return false;
  }
  out.attempt = MutationAttemptId::from_value(attempt);
  out.payload = Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(digest_bytes));
  return true;
}

}  // namespace crf
