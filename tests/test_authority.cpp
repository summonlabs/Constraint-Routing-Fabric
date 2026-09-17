// Constraint Routing Fabric -- distributed authority, fencing and replay.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

[[nodiscard]] PublisherRegistration registration(PublisherId publisher, WorkerBootId boot,
                                                 SessionId session, AuthorityScopeMask scopes,
                                                 CoordinatorEpoch epoch) {
  PublisherRegistration value;
  value.publisher = publisher;
  value.boot = boot;
  value.session = session;
  value.scopes = scopes;
  value.registered_tick = 1;
  value.registered_at = epoch;
  value.live = true;
  return value;
}

[[nodiscard]] AuthorityContext context(PublisherId publisher, WorkerBootId boot, SessionId session,
                                       CoordinatorEpoch epoch, MutationAttemptId attempt) {
  AuthorityContext value;
  value.epoch = epoch;
  value.publisher = publisher;
  value.worker_boot = boot;
  value.session = session;
  value.attempt = attempt;
  value.request = RequestId::from_value(1);
  value.scopes = all_scopes();
  return value;
}

}  // namespace

CRF_TEST(Authority, EpochsAreStrictlyMonotonicAndNeverWrap) {
  AuthorityRegistry registry;
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(1)));
  CRF_CHECK_EQ(registry.establish_epoch(CoordinatorEpoch::from_value(1)).code(),
               ErrorCode::EpochMismatch);
  CRF_CHECK_EQ(registry.establish_epoch(CoordinatorEpoch::from_value(1)).code(),
               ErrorCode::EpochMismatch);
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(2)));
  CRF_CHECK_EQ(registry.epoch().value(), std::uint64_t{2});
  CRF_CHECK_EQ(registry.establish_epoch(CoordinatorEpoch{}).code(), ErrorCode::InvalidArgument);
}

CRF_TEST(Authority, DefaultDenyOnRegistrationAndOnEveryMutation) {
  AuthorityRegistry registry;
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(4)));
  const PublisherId publisher = PublisherId::from_value(1);
  const WorkerBootId boot = WorkerBootId::from_value(100);
  const SessionId session = SessionId::from_value(9);

  // A registration without any scope authorizes nothing.
  CRF_CHECK_EQ(registry.register_publisher(registration(publisher, boot, session, 0,
                                                        CoordinatorEpoch::from_value(4)),
                                           Limits{})
                   .code(),
               ErrorCode::Unauthorized);

  // A registration bound to the wrong epoch is refused.
  CRF_CHECK_EQ(registry.register_publisher(registration(publisher, boot, session, all_scopes(),
                                                        CoordinatorEpoch::from_value(3)),
                                           Limits{})
                   .code(),
               ErrorCode::EpochMismatch);

  CRF_CHECK_STATUS(registry.register_publisher(
      registration(publisher, boot, session, all_scopes(), CoordinatorEpoch::from_value(4)),
      Limits{}));
  CRF_CHECK_EQ(registry.live_publishers(), std::size_t{1});

  // An incomplete authority context authorizes nothing.
  AuthorityContext empty;
  CRF_CHECK_EQ(registry.authorize(empty, scope_bit(AuthorityScope::ReadResults)).code(),
               ErrorCode::Unauthorized);

  // A stale epoch is refused.
  CRF_CHECK_EQ(registry
                   .authorize(context(publisher, boot, session, CoordinatorEpoch::from_value(3),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::EpochMismatch);

  // Being connected is not being authorized: a different session is refused.
  CRF_CHECK_EQ(registry
                   .authorize(context(publisher, boot, SessionId::from_value(10),
                                      CoordinatorEpoch::from_value(4),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::Unauthorized);

  // A different boot for a live publisher is stale and therefore fenced.
  CRF_CHECK_EQ(registry
                   .authorize(context(publisher, WorkerBootId::from_value(101), session,
                                      CoordinatorEpoch::from_value(4),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::Fenced);

  // Holding one scope does not grant another.
  CRF_CHECK_STATUS(registry.register_publisher(
      registration(PublisherId::from_value(2), WorkerBootId::from_value(200),
                   SessionId::from_value(20), scope_bit(AuthorityScope::ReadResults),
                   CoordinatorEpoch::from_value(4)),
      Limits{}));
  CRF_CHECK_EQ(registry
                   .authorize(context(PublisherId::from_value(2), WorkerBootId::from_value(200),
                                      SessionId::from_value(20), CoordinatorEpoch::from_value(4),
                                      MutationAttemptId::from_value(2)),
                              scope_bit(AuthorityScope::PublishConstraintSet))
                   .code(),
               ErrorCode::Unauthorized);
  CRF_CHECK_STATUS(registry.authorize(
      context(PublisherId::from_value(2), WorkerBootId::from_value(200), SessionId::from_value(20),
              CoordinatorEpoch::from_value(4), MutationAttemptId::from_value(2)),
      scope_bit(AuthorityScope::ReadResults)));
}

CRF_TEST(Authority, FencedBootsCanNeverReturn) {
  AuthorityRegistry registry;
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(1)));
  const PublisherId publisher = PublisherId::from_value(1);
  const WorkerBootId boot = WorkerBootId::from_value(100);
  const SessionId session = SessionId::from_value(9);
  CRF_CHECK_STATUS(registry.register_publisher(
      registration(publisher, boot, session, all_scopes(), CoordinatorEpoch::from_value(1)),
      Limits{}));
  CRF_CHECK_STATUS(
      registry.fence_boot(boot, CoordinatorEpoch::from_value(1), 5, Limits{}));
  CRF_CHECK(registry.is_boot_fenced(boot));
  CRF_CHECK_EQ(registry.live_publishers(), std::size_t{0});
  CRF_CHECK_EQ(registry
                   .authorize(context(publisher, boot, session, CoordinatorEpoch::from_value(1),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::Fenced);
  // Idempotent, and it stays fenced in every later epoch.
  CRF_CHECK_STATUS(registry.fence_boot(boot, CoordinatorEpoch::from_value(1), 6, Limits{}));
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(2)));
  CRF_CHECK_EQ(registry.register_publisher(
                   registration(publisher, boot, session, all_scopes(),
                                CoordinatorEpoch::from_value(2)),
                   Limits{})
                   .code(),
               ErrorCode::Fenced);
}

CRF_TEST(Authority, WorkerReincarnationFencesThePreviousBoot) {
  AuthorityRegistry registry;
  CRF_CHECK_STATUS(registry.establish_epoch(CoordinatorEpoch::from_value(1)));
  const PublisherId publisher = PublisherId::from_value(1);
  const WorkerBootId first = WorkerBootId::from_value(100);
  const WorkerBootId second = WorkerBootId::from_value(200);
  CRF_CHECK_STATUS(registry.register_publisher(
      registration(publisher, first, SessionId::from_value(1), all_scopes(),
                   CoordinatorEpoch::from_value(1)),
      Limits{}));
  CRF_CHECK_STATUS(registry.register_publisher(
      registration(publisher, second, SessionId::from_value(2), all_scopes(),
                   CoordinatorEpoch::from_value(1)),
      Limits{}));
  CRF_CHECK(registry.is_boot_fenced(first));
  CRF_CHECK(!registry.is_boot_fenced(second));
  CRF_CHECK_EQ(registry.live_publishers(), std::size_t{1});
  CRF_CHECK_EQ(registry
                   .authorize(context(publisher, first, SessionId::from_value(1),
                                      CoordinatorEpoch::from_value(1),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::Fenced);
  CRF_CHECK_STATUS(registry.authorize(
      context(publisher, second, SessionId::from_value(2), CoordinatorEpoch::from_value(1),
              MutationAttemptId::from_value(2)),
      scope_bit(AuthorityScope::ReadResults)));
}

CRF_TEST(Authority, MutationAttemptReplayIsIdempotentAndConflictIsDetected) {
  AuthorityRegistry registry;
  const Digest256 first = digest_of("payload", [](SemanticHasher& hasher) { hasher.put_u64(1); });
  const Digest256 second = digest_of("payload", [](SemanticHasher& hasher) { hasher.put_u64(2); });
  const MutationAttemptId attempt = MutationAttemptId::from_value(42);

  auto verdict = registry.observe_attempt(attempt, first, 1, Limits{});
  CRF_CHECK_RESULT(verdict);
  CRF_CHECK_EQ(verdict.value(), ReplayVerdict::Fresh);
  verdict = registry.observe_attempt(attempt, first, 2, Limits{});
  CRF_CHECK_RESULT(verdict);
  CRF_CHECK_EQ(verdict.value(), ReplayVerdict::ExactReplay);
  verdict = registry.observe_attempt(attempt, second, 3, Limits{});
  CRF_CHECK_RESULT(verdict);
  CRF_CHECK_EQ(verdict.value(), ReplayVerdict::Conflict);

  // The de-duplication window is bounded and documented.
  Limits limits;
  limits.max_mutation_attempts = 4;
  AuthorityRegistry bounded;
  for (std::uint64_t index = 1; index <= 4; ++index) {
    auto fresh = bounded.observe_attempt(MutationAttemptId::from_value(index), first, index, limits);
    CRF_CHECK_RESULT(fresh);
    CRF_CHECK_EQ(fresh.value(), ReplayVerdict::Fresh);
  }
  CRF_CHECK_EQ(bounded.attempts().size(), std::size_t{4});
  auto evicted = bounded.observe_attempt(MutationAttemptId::from_value(5), first, 5, limits);
  CRF_CHECK_RESULT(evicted);
  CRF_CHECK_EQ(evicted.value(), ReplayVerdict::Fresh);
  CRF_CHECK_EQ(bounded.attempts().size(), std::size_t{4});
  // The oldest attempt left the window, so it is fresh again; the newest is not.
  auto returned = bounded.observe_attempt(MutationAttemptId::from_value(1), first, 6, limits);
  CRF_CHECK_RESULT(returned);
  CRF_CHECK_EQ(returned.value(), ReplayVerdict::Fresh);
  auto recent = bounded.observe_attempt(MutationAttemptId::from_value(5), first, 7, limits);
  CRF_CHECK_RESULT(recent);
  CRF_CHECK_EQ(recent.value(), ReplayVerdict::ExactReplay);
}

CRF_TEST(Authority, FreshWorkerBootsAreUniqueAndNeverZero) {
  std::set<std::uint64_t> seen;
  for (int index = 0; index < 4096; ++index) {
    const WorkerBootId boot = AuthorityRegistry::fresh_worker_boot();
    CRF_CHECK(boot.is_valid());
    CRF_CHECK(seen.insert(boot.value()).second);
  }
  CRF_CHECK_EQ(seen.size(), std::size_t{4096});
}

CRF_TEST(Authority, RestoredDurableStateCarriesNoLiveAuthority) {
  AuthorityRegistry registry;
  std::vector<FencedBootRecord> fenced;
  FencedBootRecord record;
  record.boot = WorkerBootId::from_value(77);
  record.fenced_at = CoordinatorEpoch::from_value(1);
  record.fenced_tick = 3;
  fenced.push_back(record);
  registry.restore_durable_state(CoordinatorEpoch::from_value(5), fenced);
  CRF_CHECK_EQ(registry.epoch().value(), std::uint64_t{5});
  CRF_CHECK(registry.is_boot_fenced(WorkerBootId::from_value(77)));
  // Durable state is not live authority: nothing may pass authorization.
  CRF_CHECK_EQ(registry.live_publishers(), std::size_t{0});
  CRF_CHECK_EQ(registry.live_sessions(), std::size_t{0});
  CRF_CHECK_EQ(registry
                   .authorize(context(PublisherId::from_value(1), WorkerBootId::from_value(77),
                                      SessionId::from_value(1), CoordinatorEpoch::from_value(5),
                                      MutationAttemptId::from_value(1)),
                              scope_bit(AuthorityScope::ReadResults))
                   .code(),
               ErrorCode::Fenced);
}

CRF_TEST(Authority, CoordinatorRefusesPublishersWithoutAGrant) {
  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (!harness.ok()) {
    return;
  }
  AuthorityContext context_with_epoch;
  context_with_epoch.epoch = harness.value()->coordinator->epoch();
  context_with_epoch.attempt = MutationAttemptId::from_value(1);
  const Result<PublisherRegistration> refused = harness.value()->coordinator->register_publisher(
      context_with_epoch, PublisherId::from_value(99), WorkerBootId::from_value(5), all_scopes(),
      SessionId::from_value(5));
  CRF_CHECK_EQ(refused.code(), ErrorCode::Unauthorized);
  // The harness publisher itself is still registered: refusing one publisher
  // must not disturb another.
  CRF_CHECK_EQ(harness.value()->coordinator->authority().live_publishers(), std::size_t{1});

  // A registration bound to a stale epoch is refused even with a grant.
  AuthorityContext stale = context_with_epoch;
  stale.epoch = CoordinatorEpoch::from_value(9);
  const Result<PublisherRegistration> wrong_epoch = harness.value()->coordinator->register_publisher(
      stale, PublisherId::from_value(1), WorkerBootId::from_value(6), all_scopes(),
      SessionId::from_value(6));
  CRF_CHECK_EQ(wrong_epoch.code(), ErrorCode::EpochMismatch);
}

CRF_TEST(Authority, CoordinatorFencesObservedSessionLoss) {
  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (!harness.ok()) {
    return;
  }
  const WorkerBootId live_boot = harness.value()->boot;
  CRF_CHECK_EQ(harness.value()->coordinator->authority().live_publishers(), std::size_t{1});
  CRF_CHECK_STATUS(harness.value()->coordinator->fence_on_session_loss(harness.value()->session));
  CRF_CHECK(harness.value()->coordinator->authority().is_boot_fenced(live_boot));
  CRF_CHECK_EQ(harness.value()->coordinator->authority().live_publishers(), std::size_t{0});

  // Every mutating entry point now refuses the lost session.
  const Result<ConstraintSet> published = harness.value()->coordinator->publish_constraint_set(
      harness.value()->next_context(), make_set(setid(1), {max_hops(cid(1), 4)},
                                                standard_evidence()));
  CRF_CHECK(!published.ok());
}
