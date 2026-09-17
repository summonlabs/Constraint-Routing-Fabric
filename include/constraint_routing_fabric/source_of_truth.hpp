// Constraint Routing Fabric -- explicit ownership boundary with the fabric stack.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This header is the machine-readable statement of the boundary. Nothing in it
// is a claim about the physical network: it names which upstream authority the
// runtime consumes and which authority it never assumes.
#ifndef CONSTRAINT_ROUTING_FABRIC_SOURCE_OF_TRUTH_HPP
#define CONSTRAINT_ROUTING_FABRIC_SOURCE_OF_TRUTH_HPP

#include <cstdint>
#include <string_view>

namespace crf {

/// Upstream authorities this runtime consumes. Every one of them is an input;
/// Constraint Routing Fabric never computes or overrides any of them.
enum class UpstreamAuthority : std::uint8_t {
  Unset = 0,
  IdentityRegistry = 1,
  TopologyAuthority = 2,
  LinkStateAuthority = 3,
  PortConfigurationAuthority = 4,
  FabricCapabilityRegistry = 5,
  FailureDomainAuthority = 6,
  FabricEpochIssuer = 7,
  PathPlanner = 8,
  PathAuthority = 9,
  PolicyRegistry = 10,
  RouteFabric = 11,
  PathDiversityFabric = 12,
};

/// Capabilities this runtime explicitly does NOT own. Declared so that the
/// boundary can be asserted in tests instead of being asserted in prose only.
enum class NotOwned : std::uint8_t {
  IdentityTruth = 1,
  TopologyTruth = 2,
  LinkState = 3,
  PortConfiguration = 4,
  CapabilityTruth = 5,
  FailureDomainTruth = 6,
  FabricEpochIssuance = 7,
  CandidatePathDiscovery = 8,
  PathLegality = 9,
  RouteLifecycle = 10,
  EqualCostMultipath = 11,
  AdaptiveRouting = 12,
  RouteConvergence = 13,
  PathDiversity = 14,
  TrafficEngineering = 15,
  BandwidthReservation = 16,
  CongestionMeasurement = 17,
  PhysicalForwarding = 18,
};

[[nodiscard]] const char* to_string(UpstreamAuthority authority);
[[nodiscard]] const char* to_string(NotOwned capability);

/// Every capability named here is tested to be absent from the public API
/// surface (see tests/test_boundary.cpp).
[[nodiscard]] bool is_not_owned(NotOwned capability);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_SOURCE_OF_TRUTH_HPP
