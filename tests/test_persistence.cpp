// Constraint Routing Fabric -- persistence, recovery and adversarial input.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

/// A scratch directory that is removed when the test finishes.
class ScratchDir {
 public:
  explicit ScratchDir(const std::string& name) {
    path_ = std::filesystem::temp_directory_path() / ("crf_test_" + name);
    std::error_code error;
    std::filesystem::remove_all(path_, error);
    std::filesystem::create_directories(path_, error);
  }
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;
  ~ScratchDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  [[nodiscard]] std::string file(const std::string& name) const {
    return (path_ / name).string();
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_{};
};

[[nodiscard]] ConstraintSet fixture_set() {
  const EvidenceRequirements evidence = standard_evidence();
  std::vector<Constraint> constraints;
  constraints.push_back(max_hops(cid(1), 6));
  constraints.push_back(with_nodes(cid(2), ConstraintKind::RequiredNode, {nid(11)}));
  constraints.push_back(with_capabilities(cid(3), ConstraintKind::RequiredCapability, {capid(5)}));
  Constraint preference = max_latency(cid(4), LatencySource::PlannerCost, 5000);
  as_preference(preference, 1, 3);
  ConstraintSet set = make_set(setid(10), std::move(constraints), evidence);
  set.name = "persisted";
  return set;
}

[[nodiscard]] CandidatePath fixture_candidate() {
  PathSpec spec;
  spec.path = pathid(500);
  spec.nodes = {nid(10), nid(11), nid(12)};
  spec.first_link = 5000;
  spec.planner_latency_micros = 4000;
  spec.capabilities = {capid(5)};
  return build_candidate(spec, standard_evidence());
}

[[nodiscard]] PersistentState fixture_state() {
  PersistentState state;
  state.initialized = true;
  state.epoch = CoordinatorEpoch::from_value(3);
  state.evidence = standard_evidence();
  state.sets.push_back(fixture_set());
  (void)state.watermarks.advance_family(EvidenceFamily::Capability, 5);

  CandidatePopulation population;
  population.set_id = setid(10);
  population.candidates.push_back(fixture_candidate());
  state.populations.push_back(population);

  // The context points at the set, so the set must outlive it: binding a
  // temporary here would leave the evaluator with a dangling pointer.
  const ConstraintSet set = fixture_set();
  EvaluationContext context = context_for(set, standard_evidence());
  const Result<EvaluationRecord> record = evaluate_candidate(context, fixture_candidate());
  if (record.ok()) {
    state.evaluations.push_back(record.value());
    state.last_evaluation_generation = EvaluationGeneration::from_value(1);
  }
  FencedBootRecord fenced;
  fenced.boot = WorkerBootId::from_value(99);
  fenced.fenced_at = CoordinatorEpoch::from_value(2);
  fenced.fenced_tick = 10;
  state.fenced_boots.push_back(fenced);
  state.live_boots.push_back(WorkerBootId::from_value(1234));
  MutationAttemptRecord attempt;
  attempt.attempt = MutationAttemptId::from_value(7);
  attempt.payload = candidate_digest(fixture_candidate());
  attempt.recorded_tick = 11;
  state.attempts.push_back(attempt);
  return state;
}

[[nodiscard]] std::vector<std::byte> encode_state_bytes(const PersistentState& state) {
  ByteWriter writer;
  encode_persistent_state(writer, state);
  return encode_envelope(writer.span());
}

/// Decodes an envelope, mutates the state and re-encodes it so that the
/// semantic validators (not the integrity checks) are the thing under test.
template <class Mutator>
[[nodiscard]] Status revalidate_mutated(const PersistentState& base, Mutator mutate) {
  ByteWriter writer;
  encode_persistent_state(writer, base);
  ByteReader reader(writer.span());
  PersistentState state;
  if (!decode_persistent_state(reader, Limits{}, state)) {
    return Status::failure(ErrorCode::Malformed, "fixture state failed to round trip");
  }
  mutate(state);
  return validate_persistent_state(state, Limits{});
}

}  // namespace

CRF_TEST(Persistence, StateRoundTripIsExact) {
  const PersistentState state = fixture_state();
  const Digest256 digest = persistent_state_digest(state);
  ByteWriter writer;
  encode_persistent_state(writer, state);
  ByteReader reader(writer.span());
  PersistentState decoded;
  CRF_CHECK(decode_persistent_state(reader, Limits{}, decoded));
  CRF_CHECK(reader.at_end());
  CRF_CHECK_STATUS(validate_persistent_state(decoded, Limits{}));
  CRF_CHECK_EQ(persistent_state_digest(decoded), digest);
}

CRF_TEST(Persistence, EnvelopeRoundTripAndIntegrity) {
  const PersistentState state = fixture_state();
  const std::vector<std::byte> raw = encode_state_bytes(state);
  std::vector<std::byte> payload;
  CRF_CHECK_STATUS(decode_envelope(raw, Limits{}, payload));
  CRF_CHECK_EQ(payload.size(), raw.size() - 56);

  // Bad magic.
  std::vector<std::byte> bad_magic = raw;
  bad_magic[0] = std::byte{'X'};
  CRF_EXPECT_CODE(decode_envelope(bad_magic, Limits{}, payload), ErrorCode::PersistenceCorrupt);

  // Unsupported version.
  std::vector<std::byte> bad_version = raw;
  bad_version[8] = std::byte{9};
  CRF_EXPECT_CODE(decode_envelope(bad_version, Limits{}, payload), ErrorCode::UnsupportedVersion);

  // Truncation.
  std::vector<std::byte> shortened(raw.begin(), raw.end() - 1);
  CRF_EXPECT_CODE(decode_envelope(shortened, Limits{}, payload), ErrorCode::Truncated);

  // Trailing bytes.
  std::vector<std::byte> extended = raw;
  extended.push_back(std::byte{0});
  CRF_EXPECT_CODE(decode_envelope(extended, Limits{}, payload), ErrorCode::TrailingBytes);

  // A single flipped bit in the payload.
  std::vector<std::byte> flipped = raw;
  flipped[30] = static_cast<std::byte>(std::to_integer<std::uint8_t>(flipped[30]) ^ 0x01);
  CRF_EXPECT_CODE(decode_envelope(flipped, Limits{}, payload), ErrorCode::IntegrityMismatch);

  // A single flipped bit in the checksum region.
  std::vector<std::byte> checksum_flip = raw;
  checksum_flip[raw.size() - 40] =
      static_cast<std::byte>(std::to_integer<std::uint8_t>(checksum_flip[raw.size() - 40]) ^ 0x80);
  CRF_EXPECT_CODE(decode_envelope(checksum_flip, Limits{}, payload), ErrorCode::IntegrityMismatch);

  // An absurd declared payload length.
  std::vector<std::byte> absurd = raw;
  for (std::size_t index = 0; index < 8; ++index) {
    absurd[12 + index] = std::byte{0xff};
  }
  CRF_EXPECT_CODE(decode_envelope(absurd, Limits{}, payload), ErrorCode::ResourceLimit);
}

CRF_TEST(Persistence, DurableStoreRoundTripAndAtomicReplacement) {
  ScratchDir scratch("store_round_trip");
  const std::string path = scratch.file("store.bin");
  auto store = DurableStore::open(path, Limits{}, true);
  CRF_CHECK_RESULT(store);
  if (!store.ok()) {
    return;
  }
  CRF_CHECK(!store.value()->exists());
  const PersistentState state = fixture_state();
  CRF_CHECK_STATUS(store.value()->save(state));
  CRF_CHECK(store.value()->exists());
  CRF_CHECK_EQ(store.value()->successful_writes(), std::uint64_t{1});

  auto loaded = store.value()->load();
  CRF_CHECK_RESULT(loaded);
  CRF_CHECK_EQ(persistent_state_digest(loaded.value()), persistent_state_digest(state));

  // Atomic replacement leaves no temporary file behind.
  CRF_CHECK_STATUS(store.value()->save(state));
  std::error_code error;
  std::size_t entries = 0;
  for (const auto& entry : std::filesystem::directory_iterator(scratch.path(), error)) {
    if (entry.path().extension() != ".lock") {
      ++entries;
    }
  }
  CRF_CHECK_EQ(entries, std::size_t{1});

  // Saving an invalid state is refused and never reaches the file.
  PersistentState invalid = state;
  invalid.sets.push_back(state.sets.front());
  CRF_EXPECT_CODE(store.value()->save(invalid), ErrorCode::DuplicateIdentity);
  CRF_CHECK_EQ(store.value()->successful_writes(), std::uint64_t{2});
  CRF_CHECK_EQ(store.value()->failed_writes(), std::uint64_t{0});
}

CRF_TEST(Persistence, UnreadableStoreIsQuarantinedNeverDiscarded) {
  ScratchDir scratch("store_quarantine");
  const std::string path = scratch.file("store.bin");
  {
    auto store = DurableStore::open(path, Limits{}, true);
    CRF_CHECK_RESULT(store);
    if (!store.ok()) {
      return;
    }
    CRF_CHECK_STATUS(store.value()->save(fixture_state()));
  }
  // Corrupt the file on disk.
  {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    CRF_CHECK(file.good());
    if (!file.good()) {
      return;
    }
    file.seekg(40);
    char existing = 0;
    file.read(&existing, 1);
    file.clear();
    file.seekp(40);
    const char flipped = static_cast<char>(existing ^ 0x5a);
    file.write(&flipped, 1);
    file.close();
  }
  // Opening without permission to initialize refuses a store whose content does
  // not describe a valid state.
  {
    auto strict = DurableStore::open(path, Limits{}, false);
    CRF_CHECK(!strict.ok());
    CRF_CHECK_EQ(strict.code(), ErrorCode::IntegrityMismatch);
  }
  auto permissive = DurableStore::open(path, Limits{}, true);
  CRF_CHECK_RESULT(permissive);
  if (!permissive.ok()) {
    return;
  }
  // The quarantined bytes are preserved and the fresh store starts empty.
  {
    const Result<PersistentState> loaded = permissive.value()->load();
    CRF_CHECK_EQ(loaded.code(), ErrorCode::NotFound);
  }
  bool quarantined = false;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator(scratch.path(), error)) {
    const std::string name = entry.path().filename().string();
    if (name.find("quarantine") != std::string::npos) {
      quarantined = true;
    }
  }
  CRF_CHECK(quarantined);
}

CRF_TEST(Persistence, SemanticValidationRejectsAdversarialStates) {
  const PersistentState base = fixture_state();

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.sets.push_back(state.sets.front());
                 }),
                 ErrorCode::DuplicateIdentity);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.evaluations.front().set_id = setid(999);
                 }),
                 ErrorCode::NotFound);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.evaluations.push_back(state.evaluations.front());
                 }),
                 ErrorCode::DuplicateIdentity);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.evaluations.front().primary_reason = ReasonCode::ForbiddenNodePresent;
                 }),
                 ErrorCode::Malformed);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   Reason reason;
                   reason.code = ReasonCode::ForbiddenNodePresent;
                   reason.reason_class = ReasonClass::MandatoryConstraint;
                   reason.constraint = cid(2);
                   reason.constraint_ordinal = 2;
                   Reason earlier;
                   earlier.code = ReasonCode::RequiredNodeAbsent;
                   earlier.reason_class = ReasonClass::MandatoryConstraint;
                   earlier.constraint = cid(1);
                   earlier.constraint_ordinal = 1;
                   state.evaluations.front().reasons = {reason, earlier};
                   state.evaluations.front().primary_reason = reason.code;
                 }),
                 ErrorCode::Malformed);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   // A consulted family that carries no generation is a
                   // dangling evidence binding.
                   state.evaluations.front().consulted |= family_bit(EvidenceFamily::Policy);
                   state.evaluations.front().evidence.policy = PolicyGeneration{};
                 }),
                 ErrorCode::Malformed);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.last_evaluation_generation = EvaluationGeneration{};
                 }),
                 ErrorCode::ImpossibleGeneration);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   CandidatePopulation duplicate = state.populations.front();
                   state.populations.push_back(duplicate);
                 }),
                 ErrorCode::DuplicateIdentity);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.fenced_boots.push_back(state.fenced_boots.front());
                 }),
                 ErrorCode::DuplicateIdentity);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.live_boots.push_back(state.live_boots.front());
                 }),
                 ErrorCode::DuplicateIdentity);

  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   state.attempts.push_back(state.attempts.front());
                 }),
                 ErrorCode::DuplicateIdentity);

  // A set whose normalized representation contradicts itself is refused.
  CRF_EXPECT_CODE(revalidate_mutated(base, [](PersistentState& state) {
                   std::vector<Constraint> contradictory;
                   contradictory.push_back(
                       with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(5)}));
                   contradictory.push_back(
                       with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(5)}));
                   state.sets.front().constraints = contradictory;
                 }),
                 ErrorCode::IntegrityMismatch);
}

CRF_TEST(Persistence, DecodersRejectStructuredCorruption) {
  // A syntactically well-formed constraint record with an unknown kind.
  {
    Constraint valid = max_hops(cid(1), 5);
    ByteWriter writer;
    encode_constraint(writer, valid);
    std::vector<std::byte> bytes = writer.buffer();
    bytes[16] = std::byte{0};
    bytes[17] = std::byte{0};
    ByteReader reader(bytes);
    Constraint decoded;
    CRF_CHECK(!decode_constraint(reader, Limits{}, decoded));
  }
  // An impossible numeric bound for the kind.
  {
    Constraint valid = max_hops(cid(1), 5);
    ByteWriter writer;
    encode_constraint(writer, valid);
    std::vector<std::byte> bytes = writer.buffer();
    for (std::size_t index = 0; index < 8; ++index) {
      bytes[20 + index] = std::byte{0};
    }
    ByteReader reader(bytes);
    Constraint decoded;
    CRF_CHECK(!decode_constraint(reader, Limits{}, decoded));
  }
  // An impossible generation.
  {
    Constraint valid = max_hops(cid(1), 5);
    ByteWriter writer;
    encode_constraint(writer, valid);
    std::vector<std::byte> bytes = writer.buffer();
    for (std::size_t index = 0; index < 8; ++index) {
      bytes[8 + index] = std::byte{0xff};
    }
    ByteReader reader(bytes);
    Constraint decoded;
    CRF_CHECK(!decode_constraint(reader, Limits{}, decoded));
  }
  // A non-canonical entity list in durable content is corruption, not a hint.
  {
    Constraint valid = with_nodes(cid(1), ConstraintKind::RequiredNode, {nid(1), nid(2)});
    ByteWriter writer;
    encode_constraint(writer, valid);
    std::vector<std::byte> bytes = writer.buffer();
    // The node list follows the fixed 56-byte constraint prefix and its own
    // four-byte count, so the two identities live at offsets 60 and 68.
    CRF_CHECK_EQ(bytes.size(), std::size_t{96});
    if (bytes.size() == 96) {
      for (std::size_t index = 0; index < 8; ++index) {
        std::swap(bytes[60 + index], bytes[68 + index]);
      }
    }
    ByteReader reader(bytes);
    Constraint decoded;
    CRF_CHECK(!decode_constraint(reader, Limits{}, decoded));
  }
  // A durable envelope whose payload is not the declared length.
  {
    const PersistentState state = fixture_state();
    const std::vector<std::byte> raw = encode_state_bytes(state);
    std::vector<std::byte> shorter(raw.begin(), raw.end() - 1);
    std::vector<std::byte> payload;
    CRF_CHECK(!decode_envelope(shorter, Limits{}, payload).ok());
  }
}

CRF_TEST(Persistence, DurabilityBarrierRefusesToAcknowledgeAFailedWrite) {
  ScratchDir scratch("store_barrier");
  const std::string directory = scratch.file("inner");
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  const std::string path = (std::filesystem::path(directory) / "store.bin").string();
  auto store = DurableStore::open(path, Limits{}, true);
  CRF_CHECK_RESULT(store);
  if (!store.ok()) {
    return;
  }
  CRF_CHECK_STATUS(store.value()->save(fixture_state()));

  // Block the atomic replacement: the temporary file path is occupied by a
  // directory, so the next durable write cannot succeed. The store must report
  // the failure rather than pretending the write happened.
  std::filesystem::create_directories(path + ".tmp", error);
  const Status failed = store.value()->save(fixture_state());
  CRF_CHECK(!failed.ok());
  CRF_CHECK_EQ(store.value()->failed_writes(), std::uint64_t{1});
  CRF_CHECK_EQ(store.value()->successful_writes(), std::uint64_t{1});
}

CRF_TEST(Persistence, CoordinatorPersistenceRoundTripAndConservativeRecovery) {
  ScratchDir scratch("coordinator_recovery");
  const std::string path = scratch.file("coordinator.bin");
  const EvidenceRequirements evidence = standard_evidence();
  ConstraintSet published;
  const WorkerBootId first_boot = WorkerBootId::from_value(555);
  const WorkerBootId second_boot = WorkerBootId::from_value(556);
  {
    auto harness = make_harness(path, Limits{}, first_boot);
    CRF_CHECK_RESULT(harness);
    if (!harness.ok()) {
      return;
    }
    const Result<ConstraintSet> result =
        harness.value()->coordinator->publish_constraint_set(harness.value()->next_context(),
                                                             fixture_set());
    CRF_CHECK_RESULT(result);
    if (!result.ok()) {
      return;
    }
    published = result.value();
    CRF_CHECK_RESULT(harness.value()->coordinator->apply_lifecycle(
        harness.value()->next_context(), published.id, LifecycleEvent::Activate));
    const std::vector<CandidatePath> candidates = {fixture_candidate()};
    const Result<CommitOutcome> outcome =
        harness.value()->coordinator->evaluate(harness.value()->next_context(), published.id,
                                               candidates);
    CRF_CHECK_RESULT(outcome);
    CRF_CHECK(outcome.value().committed);
  }
  // Reopen: the epoch advances, definitions survive, no result is restored as
  // current, and the boot that held live authority is fenced for good.
  {
    auto harness = make_harness(path, Limits{}, second_boot);
    CRF_CHECK_RESULT(harness);
    if (!harness.ok()) {
      return;
    }
    CRF_CHECK_EQ(harness.value()->coordinator->epoch().value(), std::uint64_t{2});
    // The boot that held live authority before the restart is fenced: it can
    // never register again, in this or any later epoch.
    AuthorityContext fenced_registration;
    fenced_registration.epoch = harness.value()->coordinator->epoch();
    fenced_registration.attempt = MutationAttemptId::from_value(900);
    const Result<PublisherRegistration> fenced = harness.value()->coordinator->register_publisher(
        fenced_registration, PublisherId::from_value(1), first_boot, all_scopes(),
        SessionId::from_value(8));
    CRF_CHECK_EQ(fenced.code(), ErrorCode::Fenced);
    const Result<ConstraintSet> recovered =
        harness.value()->coordinator->get_constraint_set(published.id);
    CRF_CHECK_RESULT(recovered);
    CRF_CHECK_EQ(recovered.value().digest, published.digest);
    CRF_CHECK_EQ(recovered.value().state, ConstraintSetState::Active);
    const Result<CurrentnessReport> report =
        harness.value()->coordinator->currentness(published.id);
    CRF_CHECK_RESULT(report);
    CRF_CHECK_EQ(report.value().current_results, std::size_t{0});
    // Durable state is not live authority: the only live publisher is the one
    // this harness registered, never one restored from the store.
    CRF_CHECK_EQ(harness.value()->coordinator->authority().live_publishers(), std::size_t{1});
    CRF_CHECK_EQ(report.value().publisher_authority_live, true);
    CRF_CHECK(std::find(report.value().causes.begin(), report.value().causes.end(),
                        CurrentnessCause::RecoveredUnproven) != report.value().causes.end());

    // A context that still declares the previous incarnation's boot is refused.
    AuthorityContext replay = harness.value()->next_context();
    replay.worker_boot = first_boot;
    const std::vector<CandidatePath> single = {fixture_candidate()};
    const Result<CommitOutcome> rejected =
        harness.value()->coordinator->evaluate(replay, published.id, single);
    CRF_CHECK_EQ(rejected.code(), ErrorCode::Fenced);

    // Re-proving against current evidence restores current results.
    const Result<CommitOutcome> revalidated =
        harness.value()->coordinator->revalidate(harness.value()->next_context(), published.id);
    CRF_CHECK_RESULT(revalidated);
    if (revalidated.ok()) {
      CRF_CHECK(revalidated.value().committed);
      const Result<CurrentnessReport> after =
          harness.value()->coordinator->currentness(published.id);
      CRF_CHECK_RESULT(after);
      CRF_CHECK_EQ(after.value().current_results, std::size_t{1});
    }
  }
  // The store survives yet another restart with a strictly higher epoch.
  {
    auto harness = make_harness(path, Limits{}, WorkerBootId::from_value(557));
    CRF_CHECK_RESULT(harness);
    if (harness.ok()) {
      CRF_CHECK_EQ(harness.value()->coordinator->epoch().value(), std::uint64_t{3});
    }
  }
  // Two coordinators may not share one store: a second owner would be able to
  // roll the durable epoch backwards.
  {
    auto owner = make_harness(path, Limits{}, WorkerBootId::from_value(558));
    CRF_CHECK_RESULT(owner);
    if (owner.ok()) {
      auto second = make_harness(path, Limits{}, WorkerBootId::from_value(559));
      CRF_CHECK(!second.ok());
      CRF_CHECK_EQ(second.code(), ErrorCode::PersistenceUnavailable);
    }
  }
  // Once the owner is gone the store can be opened again.
  {
    auto harness = make_harness(path, Limits{}, WorkerBootId::from_value(560));
    CRF_CHECK_RESULT(harness);
  }
}
