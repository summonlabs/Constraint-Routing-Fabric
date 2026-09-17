// Constraint Routing Fabric -- deterministic digests and integrity checks.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_DIGEST_HPP
#define CONSTRAINT_ROUTING_FABRIC_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace crf {

/// 256-bit digest. Digests cover semantics only: timestamps, addresses, sockets,
/// thread identifiers, arrival order and diagnostic counters are never fed in.
class Digest256 {
 public:
  static constexpr std::size_t kSize = 32;

  Digest256() noexcept = default;

  [[nodiscard]] static Digest256 from_bytes(std::span<const std::byte, kSize> bytes) noexcept;
  [[nodiscard]] const std::span<const std::byte, kSize> bytes() const noexcept { return bytes_; }
  [[nodiscard]] const std::byte* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string to_hex() const;
  /// Parses exactly 64 lowercase or uppercase hex characters.
  [[nodiscard]] static bool from_hex(std::string_view text, Digest256& out) noexcept;

  friend bool operator==(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ == b.bytes_;
  }
  friend bool operator!=(const Digest256& a, const Digest256& b) noexcept { return !(a == b); }
  friend bool operator<(const Digest256& a, const Digest256& b) noexcept { return a.bytes_ < b.bytes_; }

  /// First eight bytes rendered as a big-endian unsigned integer. Used as the
  /// deterministic evaluation identity; never as a hidden ordering tie-break.
  [[nodiscard]] std::uint64_t leading_u64() const noexcept;

 private:
  std::array<std::byte, kSize> bytes_{};
};

/// Streaming SHA-256 (FIPS 180-4). Deterministic on every platform.
class Sha256 {
 public:
  Sha256() noexcept { reset(); }

  void reset() noexcept;
  void update(std::span<const std::byte> data) noexcept;
  void update(std::string_view text) noexcept;
  [[nodiscard]] Digest256 finish() noexcept;

 private:
  void compress(const std::byte* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::byte, 64> buffer_{};
  std::uint64_t total_bytes_{0};
  std::size_t buffer_used_{0};
};

/// CRC-32C (Castagnoli, reflected, polynomial 0x1EDC6F41), used as a fast
/// integrity check beside the digest.
[[nodiscard]] std::uint32_t crc32c(std::span<const std::byte> data) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view text) noexcept;

/// Canonical field feeder for semantic digests. Values are written in
/// little-endian form with explicit widths so that the same semantic content
/// always produces the same digest on every platform.
class SemanticHasher {
 public:
  SemanticHasher() = default;

  /// Domain separation: every digest starts with a stable ASCII label.
  void begin(std::string_view domain);
  void put_bool(bool value) noexcept;
  void put_u8(std::uint8_t value) noexcept;
  void put_u16(std::uint16_t value) noexcept;
  void put_u32(std::uint32_t value) noexcept;
  void put_u64(std::uint64_t value) noexcept;
  void put_i64(std::int64_t value) noexcept;
  /// Length-prefixed opaque byte string.
  void put_bytes(std::span<const std::byte> data) noexcept;
  /// Length-prefixed UTF-8 string.
  void put_string(std::string_view text) noexcept;
  void put_digest(const Digest256& digest) noexcept;
  [[nodiscard]] Digest256 finish() noexcept;

 private:
  Sha256 sha_{};
  std::array<std::byte, 8> scratch_{};
};

/// Convenience: digest a domain label plus a caller-supplied feeder.
template <class Fn>
[[nodiscard]] Digest256 digest_of(std::string_view domain, Fn&& feed) {
  SemanticHasher hasher;
  hasher.begin(domain);
  feed(hasher);
  return hasher.finish();
}

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_DIGEST_HPP
