// Constraint Routing Fabric -- snapshots, diffs, protocol and loopback transport.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <string>
#include <thread>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

[[nodiscard]] ConstraintSet snapshot_set(ConstraintSetId id, std::int64_t hops) {
  const EvidenceRequirements evidence = standard_evidence();
  std::vector<Constraint> constraints;
  constraints.push_back(max_hops(cid(1), hops));
  constraints.push_back(with_nodes(cid(2), ConstraintKind::RequiredNode, {nid(11)}));
  ConstraintSet set = make_set(id, std::move(constraints), evidence);
  set.name = "snapshot";
  return set;
}

[[nodiscard]] CandidatePath snapshot_candidate(PathId path, std::int64_t latency) {
  PathSpec spec;
  spec.path = path;
  spec.nodes = {nid(10), nid(11), nid(12)};
  spec.first_link = 6000 + path.value() * 10;
  spec.planner_latency_micros = latency;
  spec.capabilities = {capid(5)};
  return build_candidate(spec, standard_evidence());
}

}  // namespace

CRF_TEST(Snapshot, DefinitionsSnapshotIsDeterministic) {
  const ConstraintSet set = snapshot_set(setid(30), 5);
  const DefinitionsSnapshot first = snapshot_definitions(set);
  const DefinitionsSnapshot second = snapshot_definitions(set);
  CRF_CHECK_EQ(first.id, second.id);
  CRF_CHECK_EQ(first.digest, second.digest);
  CRF_CHECK_EQ(first.set_id, setid(30));
  CRF_CHECK_EQ(first.state, ConstraintSetState::Active);

  ConstraintSet renamed = set;
  renamed.name = "a different human label";
  renamed.declared_tick = 999;
  CRF_CHECK_EQ(snapshot_definitions(renamed).id, first.id);

  ConstraintSet changed = set;
  changed.constraints.front().bound = 6;
  std::vector<SetDefect> defects;
  CRF_CHECK_STATUS(canonicalize_constraint_set(changed, Limits{}, defects));
  CRF_CHECK(!(snapshot_definitions(changed).id == first.id));
}

CRF_TEST(Snapshot, ResultsSnapshotIsOrderIndependent) {
  std::vector<CandidateResultView> views;
  for (std::uint64_t index = 0; index < 4; ++index) {
    CandidateResultView view;
    view.path = pathid(700 + index);
    view.authority_generation = PathAuthorityGeneration::from_value(9);
    view.outcome = Outcome::Admissible;
    view.primary_reason = ReasonCode::None;
    view.state = ResultState::Current;
    view.evaluation_id = ConstraintEvaluationId::from_value(1000 + index);
    view.evaluation_generation = EvaluationGeneration::from_value(1 + index);
    view.digest = digest_of("view", [index](SemanticHasher& hasher) { hasher.put_u64(index); });
    views.push_back(view);
  }
  std::vector<CandidateResultView> reversed(views.rbegin(), views.rend());
  const ResultsSnapshot forward = snapshot_results(setid(30), ConstraintSetGeneration::from_value(1),
                                                   EvaluationGeneration::from_value(9), views);
  const ResultsSnapshot backward = snapshot_results(setid(30), ConstraintSetGeneration::from_value(1),
                                                    EvaluationGeneration::from_value(9), reversed);
  CRF_CHECK_EQ(forward.digest, backward.digest);
  CRF_CHECK_EQ(forward.id, backward.id);
  for (std::size_t index = 0; index + 1 < forward.entries.size(); ++index) {
    CRF_CHECK(forward.entries[index].path < forward.entries[index + 1].path);
  }
}

CRF_TEST(Snapshot, ResultDiffsReportEveryChangeClass) {
  std::vector<CandidateResultView> before_views;
  for (std::uint64_t index = 0; index < 3; ++index) {
    CandidateResultView view;
    view.path = pathid(800 + index);
    view.outcome = Outcome::Admissible;
    view.primary_reason = ReasonCode::None;
    view.state = ResultState::Current;
    view.evaluation_id = ConstraintEvaluationId::from_value(2000 + index);
    view.evaluation_generation = EvaluationGeneration::from_value(1);
    before_views.push_back(view);
  }
  const ResultsSnapshot before = snapshot_results(setid(30), ConstraintSetGeneration::from_value(1),
                                                  EvaluationGeneration::from_value(1), before_views);

  std::vector<CandidateResultView> after_views;
  CandidateResultView changed = before_views[0];
  changed.outcome = Outcome::HardConstraintFailed;
  changed.primary_reason = ReasonCode::ForbiddenNodePresent;
  after_views.push_back(changed);
  CandidateResultView currentness = before_views[1];
  currentness.state = ResultState::RevalidationRequired;
  after_views.push_back(currentness);
  CandidateResultView appeared;
  appeared.path = pathid(899);
  appeared.outcome = Outcome::Admissible;
  appeared.state = ResultState::Current;
  appeared.evaluation_id = ConstraintEvaluationId::from_value(3000);
  appeared.evaluation_generation = EvaluationGeneration::from_value(2);
  after_views.push_back(appeared);
  const ResultsSnapshot after = snapshot_results(setid(30), ConstraintSetGeneration::from_value(1),
                                                 EvaluationGeneration::from_value(2), after_views);

  const ResultsDiff diff = diff_results(before, after);
  CRF_CHECK_EQ(diff.from_snapshot, before.id);
  CRF_CHECK_EQ(diff.to_snapshot, after.id);
  CRF_CHECK_EQ(diff.changes.size(), std::size_t{4});
  const auto has = [&diff](ResultChangeKind kind, PathId path) {
    return std::any_of(diff.changes.begin(), diff.changes.end(),
                       [kind, path](const ResultChange& change) {
                         return change.kind == kind && change.path == path;
                       });
  };
  CRF_CHECK(has(ResultChangeKind::OutcomeChanged, pathid(800)));
  CRF_CHECK(has(ResultChangeKind::CurrentnessChanged, pathid(801)));
  CRF_CHECK(has(ResultChangeKind::Disappeared, pathid(802)));
  CRF_CHECK(has(ResultChangeKind::Appeared, pathid(899)));

  const std::vector<EvidenceGenerationChange> evidence_changes =
      diff_evidence_requirements(standard_evidence(), [&] {
        EvidenceRequirements advanced = standard_evidence();
        advanced.capability = CapabilityGeneration::from_value(6);
        advanced.policy = PolicyGeneration::from_value(8);
        return advanced;
      }());
  CRF_CHECK_EQ(evidence_changes.size(), std::size_t{2});
  CRF_CHECK_EQ(evidence_changes[0].family, EvidenceFamily::Capability);
  CRF_CHECK_EQ(evidence_changes[1].family, EvidenceFamily::Policy);
}

CRF_TEST(Snapshot, ConstraintSetDiffReportsAddsRemovesAndChanges) {
  const ConstraintSet before = snapshot_set(setid(30), 5);
  ConstraintSet after = before;
  after.constraints.front().bound = 9;
  after.constraints.push_back(with_capabilities(cid(3), ConstraintKind::RequiredCapability,
                                                {capid(5)}));
  std::vector<SetDefect> defects;
  CRF_CHECK_STATUS(canonicalize_constraint_set(after, Limits{}, defects));
  const ConstraintSetDiff diff = diff_constraint_sets(before, after);
  CRF_CHECK_EQ(diff.changes.size(), std::size_t{2});
  CRF_CHECK_EQ(diff.changes[0].kind, ConstraintChangeKind::Added);
  CRF_CHECK_EQ(diff.changes[1].kind, ConstraintChangeKind::Changed);
  CRF_CHECK(!diff.lifecycle_changed);
  after.state = ConstraintSetState::Suspended;
  CRF_CHECK(diff_constraint_sets(before, after).lifecycle_changed);
}

CRF_TEST(Protocol, FrameRoundTripForEveryMessageKind) {
  for (std::uint16_t raw = 1; raw <= 20; ++raw) {
    Frame frame;
    frame.header.message = static_cast<MessageId>(raw);
    frame.header.epoch = CoordinatorEpoch::from_value(3);
    frame.header.publisher = PublisherId::from_value(1);
    frame.header.worker_boot = WorkerBootId::from_value(2);
    frame.header.attempt = MutationAttemptId::from_value(3);
    frame.header.request = RequestId::from_value(4);
    frame.header.scopes = 0x7f;
    frame.payload.assign(static_cast<std::size_t>(raw), std::byte{0x11});
    std::vector<std::byte> bytes;
    CRF_CHECK_STATUS(encode_frame(frame, Limits{}, bytes));
    CRF_CHECK_EQ(bytes.size(), frame_size(static_cast<std::uint32_t>(raw)));
    Frame decoded;
    CRF_CHECK_STATUS(decode_frame(bytes, Limits{}, decoded));
    CRF_CHECK_EQ(static_cast<std::uint16_t>(decoded.header.message), raw);
    CRF_CHECK_EQ(decoded.header.epoch.value(), std::uint64_t{3});
    CRF_CHECK_EQ(decoded.header.publisher.value(), std::uint64_t{1});
    CRF_CHECK_EQ(decoded.header.scopes, std::uint32_t{0x7f});
    CRF_CHECK(decoded.payload == frame.payload);

    std::vector<std::byte> trailing = bytes;
    trailing.push_back(std::byte{0});
    CRF_EXPECT_CODE(decode_frame(trailing, Limits{}, decoded), ErrorCode::TrailingBytes);
    std::vector<std::byte> truncated(bytes.begin(), bytes.end() - 1);
    CRF_EXPECT_CODE(decode_frame(truncated, Limits{}, decoded), ErrorCode::Truncated);
    std::vector<std::byte> flipped = bytes;
    flipped[10] = static_cast<std::byte>(std::to_integer<std::uint8_t>(flipped[10]) ^ 0x40);
    CRF_EXPECT_CODE(decode_frame(flipped, Limits{}, decoded), ErrorCode::Malformed);
    std::vector<std::byte> corrupted = bytes;
    corrupted[bytes.size() - 5] =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(corrupted[bytes.size() - 5]) ^ 0xff);
    CRF_EXPECT_CODE(decode_frame(corrupted, Limits{}, decoded), ErrorCode::IntegrityMismatch);
  }
}

CRF_TEST(Protocol, AssemblerHandlesFragmentationAndRejectsAbuse) {
  Frame frame;
  frame.header.message = MessageId::Heartbeat;
  frame.payload.assign(64, std::byte{0x22});
  std::vector<std::byte> bytes;
  CRF_CHECK_STATUS(encode_frame(frame, Limits{}, bytes));

  // Byte-at-a-time fragmentation produces exactly one frame.
  FrameAssembler assembler(Limits{});
  std::size_t produced = 0;
  for (const std::byte value : bytes) {
    CRF_CHECK_STATUS(assembler.push(std::span<const std::byte>(&value, 1)));
    Frame decoded;
    bool ready = false;
    CRF_CHECK_STATUS(assembler.pop(decoded, ready));
    if (ready) {
      ++produced;
      CRF_CHECK(decoded.payload == frame.payload);
    }
  }
  CRF_CHECK_EQ(produced, std::size_t{1});
  CRF_CHECK_EQ(assembler.buffered_bytes(), std::size_t{0});

  // Two frames in one read.
  std::vector<std::byte> doubled = bytes;
  doubled.insert(doubled.end(), bytes.begin(), bytes.end());
  FrameAssembler pair(Limits{});
  CRF_CHECK_STATUS(pair.push(doubled));
  produced = 0;
  for (;;) {
    Frame decoded;
    bool ready = false;
    CRF_CHECK_STATUS(pair.pop(decoded, ready));
    if (!ready) {
      break;
    }
    ++produced;
  }
  CRF_CHECK_EQ(produced, std::size_t{2});

  // A partial upgrade cannot pin memory: the assembly bound fails closed.
  Limits tight;
  tight.max_frame_assembly_bytes = 128;
  FrameAssembler bounded(tight);
  std::vector<std::byte> filler(200, std::byte{0});
  CRF_EXPECT_CODE(bounded.push(filler), ErrorCode::ResourceLimit);
  CRF_CHECK(bounded.failed());

  // A frame header that declares an oversized payload is rejected immediately.
  FrameAssembler strict(Limits{});
  std::vector<std::byte> declared = bytes;
  for (std::size_t index = 0; index < 4; ++index) {
    declared[12 + index] = std::byte{0xff};
    declared[13 + index] = std::byte{0xff};
  }
  const Status pushed = strict.push(declared);
  CRF_CHECK(pushed.ok());
  Frame ignored;
  bool ready = false;
  CRF_CHECK(!strict.pop(ignored, ready).ok());
  CRF_CHECK(strict.failed());
}

CRF_TEST(Protocol, PayloadCodecsRoundTripAndValidate) {
  HelloPayload hello;
  hello.publisher = PublisherId::from_value(1);
  hello.worker_boot = WorkerBootId::from_value(2);
  hello.requested_scopes = 0x3f;
  hello.client_name = "client";
  ByteWriter writer;
  encode_hello(writer, hello);
  ByteReader reader(writer.span());
  HelloPayload decoded_hello;
  CRF_CHECK(decode_hello(reader, Limits{}, decoded_hello));
  CRF_CHECK(reader.at_end());
  CRF_CHECK_EQ(decoded_hello.publisher.value(), std::uint64_t{1});
  CRF_CHECK_EQ(decoded_hello.client_name, std::string("client"));

  // A zero identity is rejected rather than defaulted.
  ByteWriter zero_writer;
  zero_writer.put_u64(0);
  zero_writer.put_u64(2);
  zero_writer.put_u32(1);
  zero_writer.put_string("x");
  ByteReader zero_reader(zero_writer.span());
  HelloPayload ignored;
  CRF_CHECK(!decode_hello(zero_reader, Limits{}, ignored));

  ErrorReportPayload report;
  report.code = ErrorCode::Unauthorized;
  report.reason = ReasonCode::ScopeNotAuthorized;
  report.detail = "denied";
  ByteWriter report_writer;
  encode_error_report(report_writer, report);
  ByteReader report_reader(report_writer.span());
  ErrorReportPayload decoded_report;
  CRF_CHECK(decode_error_report(report_reader, Limits{}, decoded_report));
  CRF_CHECK_EQ(decoded_report.code, ErrorCode::Unauthorized);
  CRF_CHECK_EQ(decoded_report.reason, ReasonCode::ScopeNotAuthorized);
  CRF_CHECK_EQ(decoded_report.detail, std::string("denied"));

  // An out-of-range error code is rejected.
  ByteWriter bad_writer;
  bad_writer.put_u32(9999);
  bad_writer.put_u16(0);
  bad_writer.put_u16(0);
  bad_writer.put_string("x");
  ByteReader bad_reader(bad_writer.span());
  CRF_CHECK(!decode_error_report(bad_reader, Limits{}, decoded_report));
}

CRF_TEST(Protocol, LoopbackCoordinatorClientRoundTrip) {
  const EvidenceRequirements evidence = standard_evidence();
  auto harness = make_harness();
  CRF_CHECK_RESULT(harness);
  if (!harness.ok()) {
    return;
  }
  ServerConfig server_config;
  server_config.limits = Limits{};
  auto server = CoordinatorServer::start(*harness.value()->coordinator, server_config);
  CRF_CHECK_RESULT(server);
  if (!server.ok()) {
    return;
  }
  std::thread server_thread([&server]() { (void)server.value()->run(); });

  WorkerConfig worker_config;
  worker_config.port = server.value()->port();
  worker_config.publisher = PublisherId::from_value(1);
  worker_config.requested_scopes = all_scopes();
  worker_config.client_name = "integration";
  auto client = WorkerClient::connect(worker_config, Limits{});
  CRF_CHECK_RESULT(client);
  if (!client.ok()) {
    (void)server.value()->stop();
    server_thread.join();
    return;
  }
  CRF_CHECK(client.value()->boot().is_valid());
  CRF_CHECK(client.value()->session().is_valid());
  CRF_CHECK_EQ(client.value()->epoch().value(), harness.value()->coordinator->epoch().value());

  ConstraintSet set = snapshot_set(setid(40), 5);
  auto published = client.value()->publish_constraint_set(set);
  CRF_CHECK_RESULT(published);
  if (published.ok()) {
    CRF_CHECK_EQ(published.value().id, setid(40));
    CRF_CHECK_EQ(published.value().generation.value(), std::uint64_t{1});
    auto activated = client.value()->apply_lifecycle(setid(40), LifecycleEvent::Activate);
    CRF_CHECK_RESULT(activated);

    const std::vector<CandidatePath> candidates = {snapshot_candidate(pathid(900), 3000),
                                                   snapshot_candidate(pathid(901), 4000)};
    auto outcome = client.value()->evaluate(setid(40), candidates);
    CRF_CHECK_RESULT(outcome);
    if (outcome.ok()) {
      CRF_CHECK_EQ(outcome.value().batch.records.size(), std::size_t{2});
      CRF_CHECK_EQ(outcome.value().batch.batch_outcome,
                   BatchOutcome::AdmissibleCandidatesAvailable);
    }
    auto definitions = client.value()->query_definitions(setid(40));
    CRF_CHECK_RESULT(definitions);
    if (definitions.ok()) {
      CRF_CHECK_EQ(definitions.value().set_id, setid(40));
      CRF_CHECK_EQ(definitions.value().constraints.size(), std::size_t{2});
    }
    auto results = client.value()->query_results(setid(40));
    CRF_CHECK_RESULT(results);
    if (results.ok()) {
      CRF_CHECK_EQ(results.value().entries.size(), std::size_t{2});
    }
    auto currentness = client.value()->query_currentness(setid(40));
    CRF_CHECK_RESULT(currentness);
    if (currentness.ok()) {
      CRF_CHECK_EQ(currentness.value().current_results, std::size_t{2});
    }
    CRF_CHECK_STATUS(client.value()->heartbeat());
    // A query for an unknown set is a clean not-found rather than a transport error.
    auto missing = client.value()->query_definitions(setid(9999));
    CRF_CHECK_EQ(missing.code(), ErrorCode::NotFound);
  }
  CRF_CHECK_STATUS(client.value()->close());
  CRF_CHECK_STATUS(server.value()->stop());
  server_thread.join();
  CRF_CHECK(server.value()->sessions_accepted() >= 1);
  CRF_CHECK(server.value()->frames_handled() >= 6);
}

CRF_TEST(Protocol, BoundaryDeclarationsAreComplete) {
  const NotOwned not_owned[] = {
      NotOwned::IdentityTruth,        NotOwned::TopologyTruth,
      NotOwned::LinkState,            NotOwned::PortConfiguration,
      NotOwned::CapabilityTruth,      NotOwned::FailureDomainTruth,
      NotOwned::FabricEpochIssuance,  NotOwned::CandidatePathDiscovery,
      NotOwned::PathLegality,         NotOwned::RouteLifecycle,
      NotOwned::EqualCostMultipath,   NotOwned::AdaptiveRouting,
      NotOwned::RouteConvergence,     NotOwned::PathDiversity,
      NotOwned::TrafficEngineering,   NotOwned::BandwidthReservation,
      NotOwned::CongestionMeasurement, NotOwned::PhysicalForwarding};
  for (const NotOwned capability : not_owned) {
    CRF_CHECK(is_not_owned(capability));
    CRF_CHECK(std::string(to_string(capability)) != std::string("Unknown"));
  }
  const UpstreamAuthority authorities[] = {
      UpstreamAuthority::IdentityRegistry,      UpstreamAuthority::TopologyAuthority,
      UpstreamAuthority::LinkStateAuthority,    UpstreamAuthority::PortConfigurationAuthority,
      UpstreamAuthority::FabricCapabilityRegistry,
      UpstreamAuthority::FailureDomainAuthority, UpstreamAuthority::FabricEpochIssuer,
      UpstreamAuthority::PathPlanner,           UpstreamAuthority::PathAuthority,
      UpstreamAuthority::PolicyRegistry,        UpstreamAuthority::RouteFabric,
      UpstreamAuthority::PathDiversityFabric};
  for (const UpstreamAuthority authority : authorities) {
    CRF_CHECK(std::string(to_string(authority)) != std::string("Unknown"));
  }
  CRF_CHECK_EQ(std::string(kVersionString), std::string("1.0.0"));
  CRF_CHECK(version_string().find("1.0.0") != std::string::npos);
}
