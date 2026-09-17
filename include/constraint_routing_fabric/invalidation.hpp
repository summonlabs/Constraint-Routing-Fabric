// Constraint Routing Fabric -- precise invalidation indexes and watermarks.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_INVALIDATION_HPP
#define CONSTRAINT_ROUTING_FABRIC_INVALIDATION_HPP

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <vector>

#include "constraint_routing_fabric/constraint_set.hpp"
#include "constraint_routing_fabric/evaluation.hpp"
#include "constraint_routing_fabric/identity.hpp"
#include "constraint_routing_fabric/limits.hpp"
#include "constraint_routing_fabric/status.hpp"

namespace crf {

/// Kind of dependency key an evaluation is bound to.
enum class InvalidationKeyKind : std::uint8_t {
  ConstraintSet = 1,
  Path = 2,
  Node = 3,
  Link = 4,
  Capability = 5,
  Policy = 6,
  FailureDomain = 7,
  LocalityDomain = 8,
  IsolationClass = 9,
  Planner = 10,
  Topology = 11,
  LinkState = 12,
  PathAuthority = 13,
};

struct InvalidationKey {
  InvalidationKeyKind kind{InvalidationKeyKind::ConstraintSet};
  std::uint64_t value{0};

  friend bool operator==(const InvalidationKey& a, const InvalidationKey& b) noexcept {
    return a.kind == b.kind && a.value == b.value;
  }
  friend bool operator<(const InvalidationKey& a, const InvalidationKey& b) noexcept {
    return a.kind != b.kind ? a.kind < b.kind : a.value < b.value;
  }
};

/// Monotonic invalidation watermarks. A family watermark advances when the
/// authoritative generation of that family advances. Per-key watermarks advance
/// only for the entity that actually changed, so a single capability change
/// never invalidates unrelated evaluations.
class Watermarks {
 public:
  Watermarks() = default;

  [[nodiscard]] std::uint64_t family(EvidenceFamily family) const noexcept;
  /// Advances a family watermark. Returns false when the new value is not
  /// strictly greater than the stored value (generations never decrease).
  [[nodiscard]] bool advance_family(EvidenceFamily family, std::uint64_t generation) noexcept;

  [[nodiscard]] std::uint64_t key(const InvalidationKey& key) const noexcept;
  [[nodiscard]] bool advance_key(const InvalidationKey& key, std::uint64_t watermark) noexcept;

  [[nodiscard]] std::size_t tracked_keys() const noexcept { return keys_.size(); }
  void clear() noexcept;

  [[nodiscard]] const std::map<InvalidationKey, std::uint64_t>& keys() const noexcept { return keys_; }

 private:
  std::map<EvidenceFamily, std::uint64_t> families_{};
  std::map<InvalidationKey, std::uint64_t> keys_{};
};

/// Reverse index from dependency keys to the evaluations that used them.
class InvalidationIndex {
 public:
  InvalidationIndex() = default;

  /// Binds an evaluation to every key it actually used. Re-binding the same
  /// evaluation to the same key is idempotent.
  [[nodiscard]] Status bind(const InvalidationKey& key, const ConstraintEvaluationId& evaluation);
  [[nodiscard]] Status unbind(const ConstraintEvaluationId& evaluation);
  [[nodiscard]] std::vector<ConstraintEvaluationId> dependents(const InvalidationKey& key) const;
  /// Every tracked key whose kind is listed. Used to invalidate a whole
  /// evidence family without walking unrelated keys.
  [[nodiscard]] std::vector<InvalidationKey> keys_of_kinds(
      std::span<const InvalidationKeyKind> kinds) const;
  [[nodiscard]] bool is_bound(const ConstraintEvaluationId& evaluation) const noexcept;
  [[nodiscard]] std::size_t key_count() const noexcept { return forward_.size(); }
  [[nodiscard]] std::size_t evaluation_count() const noexcept { return reverse_.size(); }
  void clear();

  /// Index/record consistency: every forward entry has a matching reverse entry
  /// and every reverse entry has at least one forward entry.
  [[nodiscard]] Status validate() const;

  /// Bounded: refuses to grow past the limits.
  [[nodiscard]] Status check_limits(const Limits& limits) const;

 private:
  std::map<InvalidationKey, std::set<ConstraintEvaluationId>> forward_{};
  std::map<ConstraintEvaluationId, std::set<InvalidationKey>> reverse_{};
};

/// The exact dependency keys of one evaluation. A key is listed only when the
/// evaluation actually consulted it.
[[nodiscard]] std::vector<InvalidationKey> dependency_keys(const EvaluationRecord& record,
                                                           const ConstraintSet& set,
                                                           const CandidatePath& candidate,
                                                           const Limits& limits);

/// True when the evaluation is still current against the watermarks.
[[nodiscard]] bool evaluation_current(const EvaluationRecord& record,
                                      const Watermarks& watermarks) noexcept;

[[nodiscard]] const char* to_string(InvalidationKeyKind kind) noexcept;

void encode_watermarks(ByteWriter& writer, const Watermarks& watermarks);
[[nodiscard]] bool decode_watermarks(ByteReader& reader, const Limits& limits, Watermarks& out);

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_INVALIDATION_HPP
