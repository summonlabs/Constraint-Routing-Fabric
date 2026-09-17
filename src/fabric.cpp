// Constraint Routing Fabric -- version, boundary declarations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/version.hpp"

#include <string>

#include "constraint_routing_fabric/source_of_truth.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

std::string version_string() {
  return std::string(kProductName) + " " + std::string(kVersionString);
}

std::string build_string() {
  std::string text = version_string();
#if defined(_MSC_VER)
  text += " [msvc ";
  text += std::to_string(_MSC_VER);
  text += "]";
#elif defined(__clang__)
  text += " [clang ";
  text += __clang_version__;
  text += "]";
#elif defined(__GNUC__)
  text += " [gcc ";
  text += __VERSION__;
  text += "]";
#else
  text += " [unknown toolchain]";
#endif
  return text;
}

const char* to_string(ErrorCode code) {
  switch (code) {
    case ErrorCode::Ok: return "Ok";
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::Malformed: return "Malformed";
    case ErrorCode::ResourceLimit: return "ResourceLimit";
    case ErrorCode::ContradictoryConstraintSet: return "ContradictoryConstraintSet";
    case ErrorCode::DuplicateIdentity: return "DuplicateIdentity";
    case ErrorCode::UnknownConstraintKind: return "UnknownConstraintKind";
    case ErrorCode::InvalidNumericBound: return "InvalidNumericBound";
    case ErrorCode::ImpossibleGeneration: return "ImpossibleGeneration";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::Unauthorized: return "Unauthorized";
    case ErrorCode::Fenced: return "Fenced";
    case ErrorCode::EpochMismatch: return "EpochMismatch";
    case ErrorCode::StaleGeneration: return "StaleGeneration";
    case ErrorCode::IdempotentReplay: return "IdempotentReplay";
    case ErrorCode::MutationAttemptConflict: return "MutationAttemptConflict";
    case ErrorCode::PersistenceUnavailable: return "PersistenceUnavailable";
    case ErrorCode::PersistenceCorrupt: return "PersistenceCorrupt";
    case ErrorCode::DurableWriteFailed: return "DurableWriteFailed";
    case ErrorCode::IntegrityMismatch: return "IntegrityMismatch";
    case ErrorCode::UnsupportedVersion: return "UnsupportedVersion";
    case ErrorCode::Truncated: return "Truncated";
    case ErrorCode::TrailingBytes: return "TrailingBytes";
    case ErrorCode::TransportFailure: return "TransportFailure";
    case ErrorCode::ProtocolViolation: return "ProtocolViolation";
    case ErrorCode::NotSupported: return "NotSupported";
    case ErrorCode::Internal: return "Internal";
  }
  return "UnknownErrorCode";
}

const char* to_string(UpstreamAuthority authority) {
  switch (authority) {
    case UpstreamAuthority::Unset: return "Unset";
    case UpstreamAuthority::IdentityRegistry: return "IdentityRegistry";
    case UpstreamAuthority::TopologyAuthority: return "TopologyAuthority";
    case UpstreamAuthority::LinkStateAuthority: return "LinkStateAuthority";
    case UpstreamAuthority::PortConfigurationAuthority: return "PortConfigurationAuthority";
    case UpstreamAuthority::FabricCapabilityRegistry: return "FabricCapabilityRegistry";
    case UpstreamAuthority::FailureDomainAuthority: return "FailureDomainAuthority";
    case UpstreamAuthority::FabricEpochIssuer: return "FabricEpochIssuer";
    case UpstreamAuthority::PathPlanner: return "PathPlanner";
    case UpstreamAuthority::PathAuthority: return "PathAuthority";
    case UpstreamAuthority::PolicyRegistry: return "PolicyRegistry";
    case UpstreamAuthority::RouteFabric: return "RouteFabric";
    case UpstreamAuthority::PathDiversityFabric: return "PathDiversityFabric";
  }
  return "Unknown";
}

const char* to_string(NotOwned capability) {
  switch (capability) {
    case NotOwned::IdentityTruth: return "IdentityTruth";
    case NotOwned::TopologyTruth: return "TopologyTruth";
    case NotOwned::LinkState: return "LinkState";
    case NotOwned::PortConfiguration: return "PortConfiguration";
    case NotOwned::CapabilityTruth: return "CapabilityTruth";
    case NotOwned::FailureDomainTruth: return "FailureDomainTruth";
    case NotOwned::FabricEpochIssuance: return "FabricEpochIssuance";
    case NotOwned::CandidatePathDiscovery: return "CandidatePathDiscovery";
    case NotOwned::PathLegality: return "PathLegality";
    case NotOwned::RouteLifecycle: return "RouteLifecycle";
    case NotOwned::EqualCostMultipath: return "EqualCostMultipath";
    case NotOwned::AdaptiveRouting: return "AdaptiveRouting";
    case NotOwned::RouteConvergence: return "RouteConvergence";
    case NotOwned::PathDiversity: return "PathDiversity";
    case NotOwned::TrafficEngineering: return "TrafficEngineering";
    case NotOwned::BandwidthReservation: return "BandwidthReservation";
    case NotOwned::CongestionMeasurement: return "CongestionMeasurement";
    case NotOwned::PhysicalForwarding: return "PhysicalForwarding";
  }
  return "Unknown";
}

bool is_not_owned(NotOwned capability) {
  // Every capability in this enumeration is owned by another component of the
  // stack. No value of this enumeration is ever produced by this runtime, and
  // no public API in this package performs any of them. The declaration exists
  // so the boundary can be asserted instead of merely documented.
  switch (capability) {
    case NotOwned::IdentityTruth:
    case NotOwned::TopologyTruth:
    case NotOwned::LinkState:
    case NotOwned::PortConfiguration:
    case NotOwned::CapabilityTruth:
    case NotOwned::FailureDomainTruth:
    case NotOwned::FabricEpochIssuance:
    case NotOwned::CandidatePathDiscovery:
    case NotOwned::PathLegality:
    case NotOwned::RouteLifecycle:
    case NotOwned::EqualCostMultipath:
    case NotOwned::AdaptiveRouting:
    case NotOwned::RouteConvergence:
    case NotOwned::PathDiversity:
    case NotOwned::TrafficEngineering:
    case NotOwned::BandwidthReservation:
    case NotOwned::CongestionMeasurement:
    case NotOwned::PhysicalForwarding:
      return true;
  }
  return true;
}

}  // namespace crf
