// Constraint Routing Fabric -- process host used by the real-process proofs.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Two modes, both real OS processes:
//   crf_host coordinator --store <path> [--port <n>]
//   crf_host worker --port <n> --publisher <id> [--scenario publish|hold]
// Output is deterministic and machine-readable so a test can assert on it.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "constraint_routing_fabric/fabric.hpp"
#include "crf_fixture.hpp"

namespace {

using namespace crf;         // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

struct Options {
  std::string mode{};
  std::string store{};
  std::uint16_t port{0};
  std::uint64_t publisher{1};
  std::string scenario{"publish"};
  bool hold{false};
  /// Zero means "generate a fresh worker boot identity". A non-zero value is
  /// only ever used to prove that a fenced identity stays fenced.
  std::uint64_t boot{0};
};

[[nodiscard]] bool parse(int argc, char** argv, Options& options) {
  if (argc < 2) {
    return false;
  }
  options.mode = argv[1];
  for (int index = 2; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto value_of = [&](const char* prefix) -> std::string {
      return argument.substr(std::strlen(prefix));
    };
    if (argument.rfind("--store=", 0) == 0) {
      options.store = value_of("--store=");
    } else if (argument.rfind("--port=", 0) == 0) {
      options.port = static_cast<std::uint16_t>(std::stoul(value_of("--port=")));
    } else if (argument.rfind("--publisher=", 0) == 0) {
      options.publisher = std::stoull(value_of("--publisher="));
    } else if (argument.rfind("--scenario=", 0) == 0) {
      options.scenario = value_of("--scenario=");
    } else if (argument.rfind("--boot=", 0) == 0) {
      options.boot = std::stoull(value_of("--boot="));
    } else if (argument == "--hold") {
      options.hold = true;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argument.c_str());
      return false;
    }
  }
  return true;
}

[[nodiscard]] Limits host_limits() {
  Limits limits;
  limits.max_evaluations_retained = 64;
  return limits;
}

/// The deterministic synthetic population used by every process proof.
[[nodiscard]] ConstraintSet host_set() {
  const EvidenceRequirements evidence = standard_evidence();
  std::vector<Constraint> constraints;
  constraints.push_back(max_hops(cid(1), 4));
  constraints.push_back(with_nodes(cid(2), ConstraintKind::ForbiddenNode, {nid(77)}));
  constraints.push_back(max_latency(cid(3), LatencySource::PlannerCost, 9000));
  Constraint preference = max_latency(cid(4), LatencySource::PlannerCost, 5000);
  as_preference(preference, 1, 5);
  constraints.push_back(preference);
  ConstraintSet set = make_set(setid(100), std::move(constraints), evidence);
  set.name = "host";
  return set;
}

[[nodiscard]] std::vector<CandidatePath> host_candidates() {
  const EvidenceRequirements evidence = standard_evidence();
  std::vector<CandidatePath> candidates;
  PathSpec admissible;
  admissible.path = pathid(201);
  admissible.nodes = {nid(10), nid(11), nid(12)};
  admissible.first_link = 1101;
  admissible.planner_latency_micros = 4000;
  admissible.bandwidth_bits_per_second = 10000000000LL;
  admissible.has_planner_rank = true;
  admissible.planner_rank = 1;
  candidates.push_back(build_candidate(admissible, evidence));

  PathSpec forbidden;
  forbidden.path = pathid(202);
  forbidden.nodes = {nid(10), nid(77), nid(12)};
  forbidden.first_link = 1201;
  forbidden.planner_latency_micros = 3000;
  forbidden.bandwidth_bits_per_second = 10000000000LL;
  forbidden.has_planner_rank = true;
  forbidden.planner_rank = 0;
  candidates.push_back(build_candidate(forbidden, evidence));

  PathSpec slow;
  slow.path = pathid(203);
  slow.nodes = {nid(20), nid(21), nid(22)};
  slow.first_link = 1301;
  slow.planner_latency_micros = 12000;
  slow.bandwidth_bits_per_second = 10000000000LL;
  slow.has_planner_rank = true;
  slow.planner_rank = 2;
  candidates.push_back(build_candidate(slow, evidence));
  return candidates;
}

[[nodiscard]] int run_coordinator(const Options& options) {
  auto clock = std::make_unique<SteadyClock>();
  CoordinatorConfig config;
  config.limits = host_limits();
  config.store_path = options.store;
  config.allow_initialize = true;
  config.evidence = standard_evidence();
  for (std::uint64_t publisher = 1; publisher <= 8; ++publisher) {
    PublisherGrant grant;
    grant.publisher = PublisherId::from_value(publisher);
    grant.scopes = scope_bit(AuthorityScope::PublishConstraintSet) |
                   scope_bit(AuthorityScope::PublishEvaluation) |
                   scope_bit(AuthorityScope::ApplyLifecycle) |
                   scope_bit(AuthorityScope::ReadDefinitions) |
                   scope_bit(AuthorityScope::ReadResults) |
                   scope_bit(AuthorityScope::RegisterPublisher) |
                   scope_bit(AuthorityScope::AdministerFencing);
    config.grants.push_back(grant);
  }
  auto coordinator = Coordinator::open(config, clock.get());
  if (!coordinator.ok()) {
    std::printf("ERROR open %s %s\n", to_string(coordinator.code()), coordinator.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  ServerConfig server_config;
  server_config.limits = host_limits();
  server_config.port = options.port;
  auto server = CoordinatorServer::start(*coordinator.value(), server_config);
  if (!server.ok()) {
    std::printf("ERROR listen %s %s\n", to_string(server.code()), server.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  std::printf("READY PORT=%u EPOCH=%llu\n", static_cast<unsigned>(server.value()->port()),
              static_cast<unsigned long long>(coordinator.value()->epoch().value()));
  std::fflush(stdout);
  const Status served = server.value()->run();
  (void)server.value()->stop();
  if (!served.ok()) {
    std::printf("ERROR serve %s %s\n", to_string(served.code()), served.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  return 0;
}

[[nodiscard]] int run_worker(const Options& options) {
  auto clock = std::make_unique<SteadyClock>();
  WorkerConfig config;
  config.port = options.port;
  config.publisher = PublisherId::from_value(options.publisher);
  config.requested_scopes = scope_bit(AuthorityScope::PublishConstraintSet) |
                             scope_bit(AuthorityScope::PublishEvaluation) |
                             scope_bit(AuthorityScope::ApplyLifecycle) |
                             scope_bit(AuthorityScope::ReadDefinitions) |
                             scope_bit(AuthorityScope::ReadResults);
  config.client_name = "crf_host";
  config.boot = options.boot == 0 ? WorkerBootId{} : WorkerBootId::from_value(options.boot);
  auto client = WorkerClient::connect(config, host_limits());
  if (!client.ok()) {
    std::printf("ERROR connect %s %s\n", to_string(client.code()), client.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  std::printf("BOOT=%llu\n", static_cast<unsigned long long>(client.value()->boot().value()));
  std::printf("SESSION=%llu\n", static_cast<unsigned long long>(client.value()->session().value()));
  std::printf("EPOCH=%llu\n", static_cast<unsigned long long>(client.value()->epoch().value()));
  std::fflush(stdout);

  if (options.scenario == "probe") {
    std::printf("PROBE_OK\n");
    std::fflush(stdout);
    (void)client.value()->close();
    return 0;
  }

  if (options.scenario == "revalidate") {
    // Prove that the definitions survived a coordinator restart and that
    // results are re-proven rather than restored.
    auto definitions = client.value()->query_definitions(setid(100));
    if (!definitions.ok()) {
      std::printf("ERROR definitions %s %s\n", to_string(definitions.code()),
                  definitions.detail().c_str());
      std::fflush(stdout);
      return 1;
    }
    std::printf("DEFINITIONS SET=%llu STATE=%s DIGEST=%s\n",
                static_cast<unsigned long long>(definitions.value().set_id.value()),
                to_string(definitions.value().state),
                definitions.value().digest.to_hex().c_str());
    auto currentness = client.value()->query_currentness(setid(100));
    if (currentness.ok()) {
      std::printf("RECOVERED CURRENT=%zu REVALIDATION=%zu RECOVERED=%zu\n",
                  currentness.value().current_results, currentness.value().revalidation_required,
                  currentness.value().recovered_unproven);
    }
    const std::vector<CandidatePath> candidates = host_candidates();
    auto outcome = client.value()->evaluate(setid(100), candidates);
    if (!outcome.ok()) {
      std::printf("ERROR evaluate %s %s\n", to_string(outcome.code()), outcome.detail().c_str());
      std::fflush(stdout);
      return 1;
    }
    for (const EvaluationRecord& record : outcome.value().batch.records) {
      std::printf("RESULT PATH=%llu OUTCOME=%s PRIMARY=%s\n",
                  static_cast<unsigned long long>(record.path.value()), to_string(record.outcome),
                  to_string(record.primary_reason));
    }
    std::printf("SCENARIO_OK\n");
    std::fflush(stdout);
    (void)client.value()->close();
    return 0;
  }

  ConstraintSet set = host_set();
  auto published = client.value()->publish_constraint_set(set);
  if (!published.ok()) {
    std::printf("ERROR publish %s %s\n", to_string(published.code()),
                published.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  std::printf("PUBLISHED SET=%llu GEN=%llu DIGEST=%s\n",
              static_cast<unsigned long long>(published.value().id.value()),
              static_cast<unsigned long long>(published.value().generation.value()),
              published.value().digest.to_hex().c_str());

  auto activated = client.value()->apply_lifecycle(published.value().id, LifecycleEvent::Activate);
  if (!activated.ok()) {
    std::printf("ERROR activate %s %s\n", to_string(activated.code()),
                activated.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  const std::vector<CandidatePath> candidates = host_candidates();
  auto outcome = client.value()->evaluate(published.value().id, candidates);
  if (!outcome.ok()) {
    std::printf("ERROR evaluate %s %s\n", to_string(outcome.code()), outcome.detail().c_str());
    std::fflush(stdout);
    return 1;
  }
  for (const EvaluationRecord& record : outcome.value().batch.records) {
    std::printf("RESULT PATH=%llu OUTCOME=%s PRIMARY=%s\n",
                static_cast<unsigned long long>(record.path.value()), to_string(record.outcome),
                to_string(record.primary_reason));
  }
  std::string order;
  for (const RankedCandidate& entry : outcome.value().batch.admissible_order) {
    if (!order.empty()) {
      order += ",";
    }
    order += std::to_string(entry.path.value());
  }
  std::printf("RANK=%s\n", order.c_str());
  std::printf("COMMITTED=%d\n", outcome.value().committed ? 1 : 0);

  auto currentness = client.value()->query_currentness(published.value().id);
  if (currentness.ok()) {
    std::printf("CURRENTNESS CURRENT=%zu REVALIDATION=%zu RECOVERED=%zu\n",
                currentness.value().current_results, currentness.value().revalidation_required,
                currentness.value().recovered_unproven);
  }
  std::printf("SCENARIO_OK\n");
  std::fflush(stdout);

  if (options.hold) {
    std::printf("HOLDING\n");
    std::fflush(stdout);
    std::string line;
    while (std::getline(std::cin, line)) {
      if (line == "quit") {
        break;
      }
      if (line == "heartbeat") {
        const Status beat = client.value()->heartbeat();
        std::printf("HEARTBEAT %s\n", beat.ok() ? "ok" : "failed");
        std::fflush(stdout);
      }
    }
  }
  (void)client.value()->close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse(argc, argv, options)) {
    std::fprintf(stderr,
                 "usage: crf_host coordinator --store=<path> [--port=<n>]\n"
                 "       crf_host worker --port=<n> --publisher=<id> [--hold]\n");
    return 2;
  }
  if (options.mode == "coordinator") {
    return run_coordinator(options);
  }
  if (options.mode == "worker") {
    return run_worker(options);
  }
  std::fprintf(stderr, "unknown mode: %s\n", options.mode.c_str());
  return 2;
}
