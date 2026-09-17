// Constraint Routing Fabric -- typed constraint model.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_HPP
#define CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "constraint_routing_fabric/codec.hpp"
#include "constraint_routing_fabric/digest.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Typed constraint discriminators. The numeric values are protocol constants
/// and must never be renumbered.
enum class ConstraintKind : std::uint16_t {
  Unset = 0,
  MaxLatency = 1,
  MinBandwidthCapability = 2,
  RequiredNode = 3,
  ForbiddenNode = 4,
  RequiredLink = 5,
  ForbiddenLink = 6,
  RequiredTier = 7,
  ForbiddenTier = 8,
  RequiredSite = 9,
  ForbiddenSite = 10,
  LocalityScope = 11,
  IsolationClass = 12,
  RequiredCapability = 13,
  ForbiddenCapability = 14,
  RequiredFailureDomainRelation = 15,
  ForbiddenFailureDomainRelation = 16,
  AdministrativePolicy = 17,
  MaxHopCount = 18,
};

/// Hard constraints decide admissibility. Preference constraints may only order
/// candidates that are already admissible; they can never rescue a hard failure.
enum class ConstraintScope : std::uint8_t {
  Mandatory = 1,
  Preference = 2,
};

/// Latency is only ever evaluated against an explicitly named evidence model.
/// Modelled planner cost and observed latency are never mixed silently.
enum class LatencySource : std::uint8_t {
  Unset = 0,
  PlannerCost = 1,
  ObservedLatency = 2,
};

/// Authoritative domain kinds. Rack, site and zone membership is only ever read
/// from explicit authoritative identities, never derived from a name prefix.
enum class DomainKind : std::uint8_t {
  Unset = 0,
  Node = 1,
  Rack = 2,
  Site = 3,
  PowerZone = 4,
  CoolingZone = 5,
  Plane = 6,
  FailureDomain = 7,
};

enum class DomainRelation : std::uint8_t {
  Unset = 0,
  Distinct = 1,
  Shared = 2,
};

/// What happens when the authoritative evidence a mandatory constraint needs is
/// absent. Fail-closed is the default and the only safe default.
enum class UnknownPolicy : std::uint8_t {
  FailClosed = 1,
  /// Explicitly permits UNKNOWN to satisfy a *negative* (forbidden) constraint.
  /// It never permits UNKNOWN to satisfy a positive (required) constraint.
  PermitUnknownNegative = 2,
};

/// Provenance label of an evidence value. Recorded, digested and reported so a
/// reader can never mistake synthetic evidence for measured evidence.
enum class EvidenceProvenance : std::uint8_t {
  None = 0,
  FabricCapabilityRegistry = 1,
  FabricTopologyAuthority = 2,
  FabricLinkStateAuthority = 3,
  FabricFailureDomainAuthority = 4,
  FabricPolicyRegistry = 5,
  PlannerModel = 6,
  SyntheticFixture = 7,
  OperatorDeclaration = 8,
};

/// How a bandwidth capability figure was obtained. This is a *capability*
/// model, never a reservation and never a delivered-throughput measurement.
enum class CapabilityModel : std::uint8_t {
  None = 0,
  DeclaredCapabilityRegistry = 1,
  SyntheticFixture = 2,
};

enum class PlannerCostModel : std::uint8_t {
  None = 0,
  HopCountUnits = 1,
  ModelledLatencyMicros = 2,
  AdministrativeMetric = 3,
};

/// Evidence families used for currentness binding. Values are protocol constants.
enum class EvidenceFamily : std::uint8_t {
  None = 0,
  ConstraintSet = 1,
  Topology = 2,
  LinkState = 3,
  Capability = 4,
  FailureDomain = 5,
  Policy = 6,
  Planner = 7,
  PathAuthority = 8,
};

using EvidenceFamilyMask = std::uint32_t;

[[nodiscard]] constexpr EvidenceFamilyMask family_bit(EvidenceFamily family) noexcept {
  return static_cast<EvidenceFamilyMask>(1u) << static_cast<unsigned>(family);
}

/// A single typed constraint. Only the fields that belong to ::kind may be set;
/// any other populated field makes the constraint malformed. There is no
/// free-form expression language in 1.0.0.
struct Constraint {
  ConstraintId id{};
  ConstraintGeneration generation{};
  ConstraintKind kind{ConstraintKind::Unset};
  ConstraintScope scope{ConstraintScope::Mandatory};
  UnknownPolicy unknown_policy{UnknownPolicy::FailClosed};

  /// Integer fixed-point bound. Microseconds for MaxLatency, bits per second for
  /// MinBandwidthCapability, hop count for MaxHopCount, distinct-domain count
  /// for RequiredFailureDomainRelation. Never floating point.
  std::int64_t bound{0};

  LatencySource latency_source{LatencySource::Unset};
  DomainKind domain_kind{DomainKind::Unset};
  DomainRelation domain_relation{DomainRelation::Unset};

  LocalityDomainId locality_domain{};
  IsolationClassId isolation_class{};

  std::vector<NodeId> nodes{};
  std::vector<LinkId> links{};
  std::vector<TierId> tiers{};
  std::vector<SiteId> sites{};
  std::vector<CapabilityId> capabilities{};
  std::vector<PolicyId> policies{};

  /// Preference ordering metadata. Mandatory constraints must leave both at zero.
  std::uint32_t preference_rank{0};
  std::uint32_t preference_weight{0};

  friend bool operator==(const Constraint& a, const Constraint& b);
  friend bool operator!=(const Constraint& a, const Constraint& b) { return !(a == b); }
};

/// Upper bound on any fixed-point bound accepted by the runtime.
inline constexpr std::int64_t kMaxFixedPointBound = (std::int64_t{1} << 62);

/// Full structural validation of a single constraint against a limit set.
/// Rejects unknown kinds, invalid numeric bounds, wrong payload for the kind,
/// unsorted or empty entity lists, oversized lists and misused preference fields.
[[nodiscard]] Status validate_constraint(const Constraint& constraint, const Limits& limits);

/// True when both constraints carry identical semantics (identity included).
[[nodiscard]] bool semantically_equal(const Constraint& a, const Constraint& b) noexcept;

/// True when both constraints carry identical semantics ignoring identity and
/// generation. Used for equivalent-duplicate canonicalization.
[[nodiscard]] bool equivalent_payload(const Constraint& a, const Constraint& b) noexcept;

/// Total order used for canonical constraint ordering: payload first, then id.
[[nodiscard]] bool canonical_less(const Constraint& a, const Constraint& b) noexcept;

/// Canonical encoding of a constraint payload excluding identity and generation.
/// The same payload always produces the same bytes.
[[nodiscard]] std::vector<std::byte> encode_constraint_payload(const Constraint& constraint);

void feed_digest(SemanticHasher& hasher, const Constraint& constraint);

/// Persistence/wire encoding. The layout is version-independent but every reader
/// validates structure through ::validate_constraint before accepting a value.
void encode_constraint(ByteWriter& writer, const Constraint& constraint);
[[nodiscard]] bool decode_constraint(ByteReader& reader, const Limits& limits, Constraint& out);

[[nodiscard]] const char* to_string(ConstraintKind kind) noexcept;
[[nodiscard]] const char* to_string(ConstraintScope scope) noexcept;
[[nodiscard]] const char* to_string(LatencySource source) noexcept;
[[nodiscard]] const char* to_string(DomainKind kind) noexcept;
[[nodiscard]] const char* to_string(DomainRelation relation) noexcept;
[[nodiscard]] const char* to_string(UnknownPolicy policy) noexcept;
[[nodiscard]] const char* to_string(EvidenceProvenance provenance) noexcept;
[[nodiscard]] const char* to_string(CapabilityModel model) noexcept;
[[nodiscard]] const char* to_string(PlannerCostModel model) noexcept;
[[nodiscard]] const char* to_string(EvidenceFamily family) noexcept;

/// True when the constraint kind is a positive requirement (Required*).
[[nodiscard]] constexpr bool is_positive_requirement(ConstraintKind kind) noexcept {
  return kind == ConstraintKind::RequiredNode || kind == ConstraintKind::RequiredLink ||
         kind == ConstraintKind::RequiredTier || kind == ConstraintKind::RequiredSite ||
         kind == ConstraintKind::RequiredCapability ||
         kind == ConstraintKind::RequiredFailureDomainRelation ||
         kind == ConstraintKind::LocalityScope || kind == ConstraintKind::IsolationClass ||
         kind == ConstraintKind::AdministrativePolicy || kind == ConstraintKind::MaxLatency ||
         kind == ConstraintKind::MinBandwidthCapability || kind == ConstraintKind::MaxHopCount;
}

/// Evidence families the constraint must consult during evaluation. Only the
/// families actually consulted are bound into the evaluation currentness set.
[[nodiscard]] EvidenceFamilyMask evidence_families(ConstraintKind kind) noexcept;

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_CONSTRAINT_HPP
