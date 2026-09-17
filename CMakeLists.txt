cmake_minimum_required(VERSION 3.25)

project(ConstraintRoutingFabric
        VERSION 1.0.0
        DESCRIPTION "Deterministic constraint-evaluation and constrained-route-selection runtime for the Distributed Fabric Infrastructure stack"
        HOMEPAGE_URL "https://github.com/summonlabs/Constraint-Routing-Fabric"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(CRF_BUILD_TESTS        "Build the validation suites"        ON)
option(CRF_BUILD_EXAMPLES     "Build the public-API examples"      ON)
option(CRF_BUILD_BENCHMARKS   "Build the scale benchmarks"         ON)
option(CRF_BUILD_HOST         "Build the process host executable"  ON)
option(CRF_ENABLE_ASAN        "Instrument with AddressSanitizer"   OFF)
option(CRF_ENABLE_ANALYZE     "Enable the MSVC static analyzer (/analyze)" OFF)
option(CRF_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(CRF_REGISTER_CTEST     "Register suites with CTest (validation runs binaries directly)" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)

if(CRF_ENABLE_ASAN AND CRF_ENABLE_ANALYZE)
  message(FATAL_ERROR "CRF_ENABLE_ASAN and CRF_ENABLE_ANALYZE are mutually exclusive: MSVC rejects /fsanitize=address combined with /analyze.")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Warning profile (first-party targets only)
# ---------------------------------------------------------------------------
add_library(crf_warnings INTERFACE)
if(MSVC)
  target_compile_options(crf_warnings INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /EHsc /MP
    /w14242 /w14254 /w14263 /w14265 /w14287 /w14296 /w14311
    /w14545 /w14546 /w14547 /w14548 /w14619 /w14640 /w14826
    /w14905 /w14906 /w14928)
  if(CRF_WARNINGS_AS_ERRORS)
    target_compile_options(crf_warnings INTERFACE /WX)
  endif()
else()
  target_compile_options(crf_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    -Wold-style-cast -Wcast-qual -Wnon-virtual-dtor -Woverloaded-virtual
    -Wnull-dereference -Wdouble-promotion -Wformat=2)
  if(CRF_WARNINGS_AS_ERRORS)
    target_compile_options(crf_warnings INTERFACE -Werror)
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(CRF_PUBLIC_HEADERS
  include/constraint_routing_fabric/version.hpp
  include/constraint_routing_fabric/limits.hpp
  include/constraint_routing_fabric/identity.hpp
  include/constraint_routing_fabric/status.hpp
  include/constraint_routing_fabric/digest.hpp
  include/constraint_routing_fabric/codec.hpp
  include/constraint_routing_fabric/time.hpp
  include/constraint_routing_fabric/constraint.hpp
  include/constraint_routing_fabric/constraint_set.hpp
  include/constraint_routing_fabric/candidate.hpp
  include/constraint_routing_fabric/lifecycle.hpp
  include/constraint_routing_fabric/evaluation.hpp
  include/constraint_routing_fabric/evaluator.hpp
  include/constraint_routing_fabric/ordering.hpp
  include/constraint_routing_fabric/snapshot.hpp
  include/constraint_routing_fabric/invalidation.hpp
  include/constraint_routing_fabric/authority.hpp
  include/constraint_routing_fabric/persistence.hpp
  include/constraint_routing_fabric/protocol.hpp
  include/constraint_routing_fabric/net.hpp
  include/constraint_routing_fabric/coordinator.hpp
  include/constraint_routing_fabric/worker.hpp
  include/constraint_routing_fabric/messages.hpp
  include/constraint_routing_fabric/server.hpp
  include/constraint_routing_fabric/source_of_truth.hpp
  include/constraint_routing_fabric/fabric.hpp)

set(CRF_SOURCES
  src/digest.cpp
  src/codec.cpp
  src/limits.cpp
  src/time.cpp
  src/identity.cpp
  src/evaluation.cpp
  src/constraint.cpp
  src/constraint_set.cpp
  src/candidate.cpp
  src/lifecycle.cpp
  src/evaluator.cpp
  src/ordering.cpp
  src/snapshot.cpp
  src/invalidation.cpp
  src/authority.cpp
  src/persistence.cpp
  src/protocol.cpp
  src/net.cpp
  src/coordinator.cpp
  src/worker.cpp
  src/messages.cpp
  src/server.cpp
  src/fabric.cpp)

add_library(ConstraintRoutingFabric ${CRF_SOURCES} ${CRF_PUBLIC_HEADERS})
add_library(SummonSoftwareLabs::ConstraintRoutingFabric ALIAS ConstraintRoutingFabric)

target_include_directories(ConstraintRoutingFabric
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(ConstraintRoutingFabric PUBLIC cxx_std_20)
set_target_properties(ConstraintRoutingFabric PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})
# The warning profile is a build-time-only dependency: it must not appear in
# the exported target interface.
target_link_libraries(ConstraintRoutingFabric PRIVATE $<BUILD_INTERFACE:crf_warnings>)

if(WIN32)
  target_link_libraries(ConstraintRoutingFabric PUBLIC ws2_32)
endif()

if(EMSCRIPTEN OR APPLE)
  target_compile_definitions(ConstraintRoutingFabric PRIVATE CRF_PLATFORM_POSIX=1)
endif()

if(CRF_ENABLE_ANALYZE)
  if(NOT MSVC)
    message(FATAL_ERROR "CRF_ENABLE_ANALYZE requires MSVC (/analyze).")
  endif()
  target_compile_options(ConstraintRoutingFabric PRIVATE /analyze /analyze:external-)
endif()

# The MSVC AddressSanitizer runtime is not installed beside every Visual Studio
# toolset. When the selected toolset does not carry it, point CRF_ASAN_RUNTIME_DIR
# at a directory that does (the "lib\x64" directory of a toolset that ships
# clang_rt.asan_dynamic-x86_64.lib). The matching runtime DLL directory must also
# be on PATH when the instrumented binaries are executed.
set(CRF_ASAN_RUNTIME_DIR "" CACHE PATH
    "Directory containing the MSVC AddressSanitizer runtime libraries")

function(crf_enable_asan target)
  if(NOT MSVC)
    message(FATAL_ERROR "CRF_ENABLE_ASAN is wired for the MSVC x64 AddressSanitizer runtime.")
  endif()
  target_compile_options(${target} PRIVATE /fsanitize=address /Zi /Oy-)
  target_link_options(${target} PRIVATE /INCREMENTAL:NO)
  if(CRF_ASAN_RUNTIME_DIR)
    target_link_directories(${target} PRIVATE "${CRF_ASAN_RUNTIME_DIR}")
  endif()
endfunction()

if(CRF_ENABLE_ASAN)
  crf_enable_asan(ConstraintRoutingFabric)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS ConstraintRoutingFabric
        EXPORT ConstraintRoutingFabricTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ConstraintRoutingFabricTargets
        FILE ConstraintRoutingFabricTargets.cmake
        NAMESPACE SummonSoftwareLabs::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ConstraintRoutingFabric)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ConstraintRoutingFabricConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ConstraintRoutingFabricConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ConstraintRoutingFabric)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/ConstraintRoutingFabricConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ConstraintRoutingFabricConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/ConstraintRoutingFabricConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ConstraintRoutingFabric)

install(FILES LICENSE README.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ConstraintRoutingFabric)

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
if(CRF_BUILD_HOST)
  add_subdirectory(host)
endif()
if(CRF_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(CRF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(CRF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
