// Constraint Routing Fabric -- canonical binary encoding primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_CODEC_HPP
#define CONSTRAINT_ROUTING_FABRIC_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crf {

/// Little-endian canonical writer. Raw C++ object layouts are never written.
class ByteWriter {
 public:
  ByteWriter() = default;

  void put_u8(std::uint8_t value);
  void put_u16(std::uint16_t value);
  void put_u32(std::uint32_t value);
  void put_u64(std::uint64_t value);
  void put_i64(std::int64_t value);
  void put_bool(bool value);
  /// Length-prefixed (u32) byte string.
  void put_bytes(std::span<const std::byte> data);
  /// Length-prefixed (u32) UTF-8 string.
  void put_string(std::string_view text);
  void put_raw(std::span<const std::byte> data);

  [[nodiscard]] const std::vector<std::byte>& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::span<const std::byte> span() const noexcept {
    return std::span<const std::byte>(buffer_.data(), buffer_.size());
  }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }

 private:
  std::vector<std::byte> buffer_{};
};

/// Bounds-checked reader. Every accessor returns false and leaves the reader
/// failed when the buffer is exhausted; a failed reader never recovers.
class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) noexcept : data_(data) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] bool at_end() const noexcept { return position_ == data_.size(); }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] std::size_t remaining() const noexcept {
    return ok_ ? data_.size() - position_ : 0;
  }
  [[nodiscard]] std::span<const std::byte> rest() const noexcept;

  bool u8(std::uint8_t& out) noexcept;
  bool u16(std::uint16_t& out) noexcept;
  bool u32(std::uint32_t& out) noexcept;
  bool u64(std::uint64_t& out) noexcept;
  bool i64(std::int64_t& out) noexcept;
  bool boolean(bool& out) noexcept;
  bool bytes(std::vector<std::byte>& out) noexcept;
  bool string(std::string& out) noexcept;
  /// Reads exactly out.size() bytes with no length prefix.
  bool raw(std::span<std::byte> out) noexcept;

  /// Reads a length prefix and rejects it when it exceeds \p max_len.
  bool bounded_length(std::uint32_t max_len, std::uint32_t& out) noexcept;

  /// Marks the reader failed. Used by callers that detect a violation that is
  /// not a simple bounds problem.
  void fail() noexcept { ok_ = false; }

 private:
  [[nodiscard]] bool ensure(std::size_t count) noexcept;

  std::span<const std::byte> data_{};
  std::size_t position_{0};
  bool ok_{true};
};

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_CODEC_HPP
