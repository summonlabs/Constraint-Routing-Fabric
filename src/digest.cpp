// Constraint Routing Fabric -- digests and integrity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/digest.hpp"

#include <array>
#include <cstring>

namespace crf {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

/// Rotate right by a count in 0..31. Every call site uses a compile-time
/// constant in 1..31; the mask states that invariant explicitly so the shift is
/// well defined for the analyzer and for the optimizer.
[[nodiscard]] constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned count) noexcept {
  const unsigned amount = count & 31u;
  return (value >> amount) | (value << ((32u - amount) & 31u));
}

[[nodiscard]] std::uint32_t read_big_endian_u32(const std::byte* data) noexcept {
  return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[0])) << 24) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[1])) << 16) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[2])) << 8) |
         static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[3]));
}

void write_big_endian_u32(std::uint32_t value, std::byte* out) noexcept {
  out[0] = static_cast<std::byte>((value >> 24) & 0xffu);
  out[1] = static_cast<std::byte>((value >> 16) & 0xffu);
  out[2] = static_cast<std::byte>((value >> 8) & 0xffu);
  out[3] = static_cast<std::byte>(value & 0xffu);
}

[[nodiscard]] const std::array<std::uint32_t, 256>& crc32c_table() {
  static const std::array<std::uint32_t, 256> table = [] {
    std::array<std::uint32_t, 256> generated{};
    for (std::uint32_t index = 0; index < 256; ++index) {
      // The mask restates the loop bound so the subscript is provably in range.
      const std::uint32_t bounded = index & 0xffu;
      std::uint32_t value = bounded;
      for (int bit = 0; bit < 8; ++bit) {
        value = (value & 1u) != 0u ? (value >> 1) ^ 0x82f63b78u : (value >> 1);
      }
      generated.data()[static_cast<std::size_t>(bounded)] = value;
    }
    return generated;
  }();
  return table;
}

}  // namespace

Digest256 Digest256::from_bytes(std::span<const std::byte, kSize> bytes) noexcept {
  Digest256 digest;
  for (std::size_t index = 0; index < kSize; ++index) {
    digest.bytes_[index] = bytes[index];
  }
  return digest;
}

bool Digest256::is_zero() const noexcept {
  for (const std::byte value : bytes_) {
    if (value != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::string Digest256::to_hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string text;
  text.reserve(kSize * 2);
  for (const std::byte value : bytes_) {
    const auto raw = std::to_integer<std::uint8_t>(value);
    text.push_back(kHex[(raw >> 4) & 0x0fu]);
    text.push_back(kHex[raw & 0x0fu]);
  }
  return text;
}

bool Digest256::from_hex(std::string_view text, Digest256& out) noexcept {
  if (text.size() != kSize * 2) {
    return false;
  }
  Digest256 parsed;
  for (std::size_t index = 0; index < kSize; ++index) {
    unsigned value = 0;
    for (int half = 0; half < 2; ++half) {
      const char character = text[index * 2 + static_cast<std::size_t>(half)];
      unsigned digit = 0;
      if (character >= '0' && character <= '9') {
        digit = static_cast<unsigned>(character - '0');
      } else if (character >= 'a' && character <= 'f') {
        digit = static_cast<unsigned>(character - 'a') + 10u;
      } else if (character >= 'A' && character <= 'F') {
        digit = static_cast<unsigned>(character - 'A') + 10u;
      } else {
        return false;
      }
      value = (value << 4) | digit;
    }
    parsed.bytes_[index] = static_cast<std::byte>(value);
  }
  out = parsed;
  return true;
}

std::uint64_t Digest256::leading_u64() const noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8) | static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes_[index]));
  }
  return value;
}

void Sha256::reset() noexcept {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  buffer_.fill(std::byte{0});
  total_bytes_ = 0;
  buffer_used_ = 0;
}

void Sha256::compress(const std::byte* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t index = 0; index < 16; ++index) {
    schedule[index] = read_big_endian_u32(block + index * 4);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = rotate_right(schedule[index - 15], 7) ^
                             rotate_right(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
    const std::uint32_t s1 = rotate_right(schedule[index - 2], 17) ^
                             rotate_right(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + choose + kRoundConstants[index] + schedule[index];
    const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::byte> data) noexcept {
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  if (buffer_used_ != 0) {
    const std::size_t needed = 64 - buffer_used_;
    const std::size_t take = data.size() < needed ? data.size() : needed;
    for (std::size_t index = 0; index < take; ++index) {
      buffer_[buffer_used_ + index] = data[index];
    }
    buffer_used_ += take;
    offset = take;
    if (buffer_used_ == 64) {
      compress(buffer_.data());
      buffer_used_ = 0;
    }
  }
  while (data.size() - offset >= 64) {
    compress(data.data() + offset);
    offset += 64;
  }
  while (offset < data.size()) {
    buffer_[buffer_used_++] = data[offset++];
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Digest256 Sha256::finish() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8u;
  const std::byte terminator{0x80};
  update(std::span<const std::byte>(&terminator, 1));
  const std::byte zero{0};
  while (buffer_used_ != 56) {
    update(std::span<const std::byte>(&zero, 1));
  }
  std::array<std::byte, 8> length_bytes{};
  for (std::size_t index = 0; index < 8; ++index) {
    length_bytes[index] = static_cast<std::byte>((bit_length >> ((7 - index) * 8)) & 0xffu);
  }
  update(std::span<const std::byte>(length_bytes));

  std::array<std::byte, Digest256::kSize> output{};
  for (std::size_t index = 0; index < 8; ++index) {
    write_big_endian_u32(state_[index], output.data() + index * 4);
  }
  return Digest256::from_bytes(std::span<const std::byte, Digest256::kSize>(output));
}

std::uint32_t crc32c(std::span<const std::byte> data) noexcept {
  const auto& table = crc32c_table();
  std::uint32_t crc = 0xffffffffu;
  for (const std::byte value : data) {
    crc = table[(crc ^ std::to_integer<std::uint8_t>(value)) & 0xffu] ^ (crc >> 8);
  }
  return crc ^ 0xffffffffu;
}

std::uint32_t crc32c(std::string_view text) noexcept {
  return crc32c(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void SemanticHasher::begin(std::string_view domain) {
  put_string(domain);
}

void SemanticHasher::put_bool(bool value) noexcept {
  put_u8(value ? std::uint8_t{1} : std::uint8_t{0});
}

void SemanticHasher::put_u8(std::uint8_t value) noexcept {
  scratch_[0] = static_cast<std::byte>(value);
  sha_.update(std::span<const std::byte>(scratch_.data(), 1));
}

void SemanticHasher::put_u16(std::uint16_t value) noexcept {
  scratch_[0] = static_cast<std::byte>(value & 0xffu);
  scratch_[1] = static_cast<std::byte>((value >> 8) & 0xffu);
  sha_.update(std::span<const std::byte>(scratch_.data(), 2));
}

void SemanticHasher::put_u32(std::uint32_t value) noexcept {
  for (std::size_t index = 0; index < 4; ++index) {
    scratch_[index] = static_cast<std::byte>((value >> (index * 8)) & 0xffu);
  }
  sha_.update(std::span<const std::byte>(scratch_.data(), 4));
}

void SemanticHasher::put_u64(std::uint64_t value) noexcept {
  for (std::size_t index = 0; index < 8; ++index) {
    scratch_[index] = static_cast<std::byte>((value >> (index * 8)) & 0xffu);
  }
  sha_.update(std::span<const std::byte>(scratch_.data(), 8));
}

void SemanticHasher::put_i64(std::int64_t value) noexcept {
  put_u64(static_cast<std::uint64_t>(value));
}

void SemanticHasher::put_bytes(std::span<const std::byte> data) noexcept {
  put_u64(static_cast<std::uint64_t>(data.size()));
  sha_.update(data);
}

void SemanticHasher::put_string(std::string_view text) noexcept {
  put_bytes(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void SemanticHasher::put_digest(const Digest256& digest) noexcept {
  sha_.update(std::span<const std::byte>(digest.data(), Digest256::kSize));
}

Digest256 SemanticHasher::finish() noexcept {
  return sha_.finish();
}

}  // namespace crf
