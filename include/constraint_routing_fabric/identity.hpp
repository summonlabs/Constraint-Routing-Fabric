// Constraint Routing Fabric -- strongly typed identities and generations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_IDENTITY_HPP
#define CONSTRAINT_ROUTING_FABRIC_IDENTITY_HPP

#include <compare>
#include <cstdint>
#include <limits>
#include <string>

namespace crf {

/// Strongly typed 64-bit identifier. Value zero is never valid for any domain.
/// There is no implicit conversion between identity domains and no implicit
/// conversion to or from the underlying integer.
template <class Tag>
class StrongId {
 public:
  using rep_type = std::uint64_t;

  constexpr StrongId() noexcept = default;

  [[nodiscard]] static constexpr StrongId from_value(rep_type value) noexcept {
    return StrongId(value);
  }
  [[nodiscard]] static constexpr bool is_valid_value(rep_type value) noexcept { return value != 0; }
  [[nodiscard]] constexpr rep_type value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_valid() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(StrongId a, StrongId b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(StrongId a, StrongId b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  explicit constexpr StrongId(rep_type value) noexcept : value_(value) {}
  rep_type value_{};
};

/// Strongly typed monotonic generation. Valid generations start at 1 and
/// increase strictly; zero means "not set". Generations never wrap: ::next()
/// fails once kMaxGeneration is reached.
template <class Tag>
class Generation {
 public:
  using rep_type = std::uint64_t;
  static constexpr rep_type kMaxGeneration = (std::numeric_limits<rep_type>::max)() / 2;

  constexpr Generation() noexcept = default;

  [[nodiscard]] static constexpr Generation from_value(rep_type value) noexcept {
    return Generation(value);
  }
  /// Builds a generation, rejecting zero and values above kMaxGeneration.
  [[nodiscard]] static constexpr bool is_representable(rep_type value) noexcept {
    return value != 0 && value <= kMaxGeneration;
  }
  [[nodiscard]] constexpr rep_type value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_valid() const noexcept { return value_ != 0; }

  /// Returns true and sets \p out when this generation can be advanced. An
  /// unset generation (zero) advances to one, so a counter that starts unset
  /// still produces strictly increasing values. The only failure is the
  /// absolute ceiling, where advancing would be impossible without wrapping.
  [[nodiscard]] bool next(Generation& out) const noexcept {
    if (value_ >= kMaxGeneration) {
      return false;
    }
    out = Generation(value_ + 1);
    return true;
  }

  friend constexpr bool operator==(Generation a, Generation b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Generation a, Generation b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  explicit constexpr Generation(rep_type value) noexcept : value_(value) {}
  rep_type value_{};
};

// --- identity domains --------------------------------------------------------
struct ConstraintSetIdTag {};
struct ConstraintSetGenerationTag {};
struct ConstraintIdTag {};
struct ConstraintGenerationTag {};
struct ConstraintEvaluationIdTag {};
struct EvaluationGenerationTag {};
struct PathIdTag {};
struct PathAuthorityGenerationTag {};
struct TopologyGenerationTag {};
struct LinkStateGenerationTag {};
struct CapabilityGenerationTag {};
struct FailureDomainGenerationTag {};
struct PolicyGenerationTag {};
struct PlannerGenerationTag {};
struct NodeIdTag {};
struct LinkIdTag {};
struct TierIdTag {};
struct SiteIdTag {};
struct LocalityDomainIdTag {};
struct FailureDomainIdTag {};
struct CapabilityIdTag {};
struct PolicyIdTag {};
struct IsolationClassIdTag {};
struct PublisherIdTag {};
struct WorkerBootIdTag {};
struct CoordinatorEpochTag {};
struct MutationAttemptIdTag {};
struct SnapshotIdTag {};
struct RequestIdTag {};
struct SessionIdTag {};

using ConstraintSetId = StrongId<ConstraintSetIdTag>;
using ConstraintId = StrongId<ConstraintIdTag>;
using ConstraintEvaluationId = StrongId<ConstraintEvaluationIdTag>;
using PathId = StrongId<PathIdTag>;
using NodeId = StrongId<NodeIdTag>;
using LinkId = StrongId<LinkIdTag>;
using TierId = StrongId<TierIdTag>;
using SiteId = StrongId<SiteIdTag>;
using LocalityDomainId = StrongId<LocalityDomainIdTag>;
using FailureDomainId = StrongId<FailureDomainIdTag>;
using CapabilityId = StrongId<CapabilityIdTag>;
using PolicyId = StrongId<PolicyIdTag>;
using IsolationClassId = StrongId<IsolationClassIdTag>;
using PublisherId = StrongId<PublisherIdTag>;
using WorkerBootId = StrongId<WorkerBootIdTag>;
using MutationAttemptId = StrongId<MutationAttemptIdTag>;
using SnapshotId = StrongId<SnapshotIdTag>;
using RequestId = StrongId<RequestIdTag>;
using SessionId = StrongId<SessionIdTag>;

using ConstraintSetGeneration = Generation<ConstraintSetGenerationTag>;
using ConstraintGeneration = Generation<ConstraintGenerationTag>;
using EvaluationGeneration = Generation<EvaluationGenerationTag>;
using PathAuthorityGeneration = Generation<PathAuthorityGenerationTag>;
using TopologyGeneration = Generation<TopologyGenerationTag>;
using LinkStateGeneration = Generation<LinkStateGenerationTag>;
using CapabilityGeneration = Generation<CapabilityGenerationTag>;
using FailureDomainGeneration = Generation<FailureDomainGenerationTag>;
using PolicyGeneration = Generation<PolicyGenerationTag>;
using PlannerGeneration = Generation<PlannerGenerationTag>;
using CoordinatorEpoch = Generation<CoordinatorEpochTag>;

/// Deterministic textual rendering used by explanations, diagnostics and tests.
/// Rendering is stable across platforms and is not used as a sort key.
[[nodiscard]] std::string to_string(ConstraintSetId value);
[[nodiscard]] std::string to_string(ConstraintId value);
[[nodiscard]] std::string to_string(ConstraintEvaluationId value);
[[nodiscard]] std::string to_string(PathId value);
[[nodiscard]] std::string to_string(NodeId value);
[[nodiscard]] std::string to_string(LinkId value);
[[nodiscard]] std::string to_string(PublisherId value);
[[nodiscard]] std::string to_string(WorkerBootId value);
[[nodiscard]] std::string to_string(MutationAttemptId value);
[[nodiscard]] std::string to_string(RequestId value);
[[nodiscard]] std::string to_string(CoordinatorEpoch value);
[[nodiscard]] std::string to_string(ConstraintSetGeneration value);
[[nodiscard]] std::string to_string(ConstraintGeneration value);
[[nodiscard]] std::string to_string(EvaluationGeneration value);
[[nodiscard]] std::string to_string(PathAuthorityGeneration value);
[[nodiscard]] std::string to_string(TopologyGeneration value);
[[nodiscard]] std::string to_string(LinkStateGeneration value);
[[nodiscard]] std::string to_string(CapabilityGeneration value);
[[nodiscard]] std::string to_string(FailureDomainGeneration value);
[[nodiscard]] std::string to_string(PolicyGeneration value);
[[nodiscard]] std::string to_string(PlannerGeneration value);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_IDENTITY_HPP
