// Constraint Routing Fabric -- canonical encoding primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/codec.hpp"

namespace crf {

void ByteWriter::put_u8(std::uint8_t value) {
  buffer_.push_back(static_cast<std::byte>(value));
}

void ByteWriter::put_u16(std::uint16_t value) {
  put_u8(static_cast<std::uint8_t>(value & 0xffu));
  put_u8(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

void ByteWriter::put_u32(std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    put_u8(static_cast<std::uint8_t>((value >> (index * 8)) & 0xffu));
  }
}

void ByteWriter::put_u64(std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    put_u8(static_cast<std::uint8_t>((value >> (index * 8)) & 0xffu));
  }
}

void ByteWriter::put_i64(std::int64_t value) {
  put_u64(static_cast<std::uint64_t>(value));
}

void ByteWriter::put_bool(bool value) {
  put_u8(value ? std::uint8_t{1} : std::uint8_t{0});
}

void ByteWriter::put_bytes(std::span<const std::byte> data) {
  put_u32(static_cast<std::uint32_t>(data.size()));
  put_raw(data);
}

void ByteWriter::put_string(std::string_view text) {
  put_u32(static_cast<std::uint32_t>(text.size()));
  put_raw(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

void ByteWriter::put_raw(std::span<const std::byte> data) {
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

std::span<const std::byte> ByteReader::rest() const noexcept {
  if (!ok_ || position_ > data_.size()) {
    return {};
  }
  return data_.subspan(position_);
}

bool ByteReader::ensure(std::size_t count) noexcept {
  if (!ok_) {
    return false;
  }
  if (count > data_.size() - position_) {
    ok_ = false;
    return false;
  }
  return true;
}

bool ByteReader::u8(std::uint8_t& out) noexcept {
  if (!ensure(1)) {
    return false;
  }
  out = std::to_integer<std::uint8_t>(data_[position_]);
  ++position_;
  return true;
}

bool ByteReader::u16(std::uint16_t& out) noexcept {
  if (!ensure(2)) {
    return false;
  }
  out = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data_[position_])) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(
                                     std::to_integer<std::uint8_t>(data_[position_ + 1]))
                                 << 8));
  position_ += 2;
  return true;
}

bool ByteReader::u32(std::uint32_t& out) noexcept {
  if (!ensure(4)) {
    return false;
  }
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data_[position_ + index]))
             << (index * 8);
  }
  position_ += 4;
  out = value;
  return true;
}

bool ByteReader::u64(std::uint64_t& out) noexcept {
  if (!ensure(8)) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data_[position_ + index]))
             << (index * 8);
  }
  position_ += 8;
  out = value;
  return true;
}

bool ByteReader::i64(std::int64_t& out) noexcept {
  std::uint64_t raw = 0;
  if (!u64(raw)) {
    return false;
  }
  out = static_cast<std::int64_t>(raw);
  return true;
}

bool ByteReader::boolean(bool& out) noexcept {
  std::uint8_t raw = 0;
  if (!u8(raw)) {
    return false;
  }
  if (raw > 1) {
    ok_ = false;
    return false;
  }
  out = raw == 1;
  return true;
}

bool ByteReader::bounded_length(std::uint32_t max_len, std::uint32_t& out) noexcept {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  if (length > max_len) {
    ok_ = false;
    return false;
  }
  out = length;
  return true;
}

bool ByteReader::raw(std::span<std::byte> out) noexcept {
  if (!ensure(out.size())) {
    return false;
  }
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = data_[position_ + index];
  }
  position_ += out.size();
  return true;
}

bool ByteReader::bytes(std::vector<std::byte>& out) noexcept {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  if (!ensure(length)) {
    return false;
  }
  out.assign(data_.begin() + static_cast<std::ptrdiff_t>(position_),
             data_.begin() + static_cast<std::ptrdiff_t>(position_ + length));
  position_ += length;
  return true;
}

bool ByteReader::string(std::string& out) noexcept {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  if (!ensure(length)) {
    return false;
  }
  out.assign(reinterpret_cast<const char*>(data_.data() + position_), length);
  position_ += length;
  return true;
}

}  // namespace crf
