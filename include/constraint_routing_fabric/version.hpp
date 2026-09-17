// Constraint Routing Fabric -- version and format constants.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTRAINT_ROUTING_FABRIC_VERSION_HPP
#define CONSTRAINT_ROUTING_FABRIC_VERSION_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace crf {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;
inline constexpr std::string_view kVersionString = "1.0.0";
inline constexpr std::string_view kProductName = "Constraint Routing Fabric";

/// Version of the durable persistence envelope. Refused when it does not match exactly.
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;

/// Version of the distributed wire protocol. Refused when it does not match exactly.
inline constexpr std::uint16_t kProtocolVersion = 1;

/// Magic prefix of every wire frame ("CRFF" little endian).
inline constexpr std::uint32_t kWireMagic = 0x46465243u;

/// Magic prefix of every persistence envelope ("CRFSTORE").
inline constexpr char kStoreMagic[8] = {'C', 'R', 'F', 'S', 'T', 'O', 'R', 'E'};

[[nodiscard]] std::string version_string();
[[nodiscard]] std::string build_string();

}  // namespace crf

#endif  // CONSTRAINT_ROUTING_FABRIC_VERSION_HPP
