file(GLOB CRF_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp")
add_executable(crf_tests ${CRF_TEST_SOURCES})
target_link_libraries(crf_tests PRIVATE ConstraintRoutingFabric crf_warnings)
target_include_directories(crf_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# Test assertions intentionally compare values of different integer widths and
# signedness (for example std::size_t against std::uint32_t). The comparison is
# the point of the assertion, so the two integral-mix diagnostics are silenced
# for the test target only. The library itself keeps the full warning profile.
if(MSVC)
  target_compile_options(crf_tests PRIVATE /wd4389 /wd4805)
endif()
set_target_properties(crf_tests PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
if(CRF_ENABLE_ASAN)
  crf_enable_asan(crf_tests)
endif()
if(CRF_ENABLE_ANALYZE)
  target_compile_options(crf_tests PRIVATE /analyze /analyze:external-)
endif()
# The real-process proofs drive the host executable, so the test binary needs
# its exact path.
if(TARGET crf_host)
  target_compile_definitions(crf_tests PRIVATE CRF_HOST_EXECUTABLE="$<TARGET_FILE:crf_host>")
endif()

# The instrumentation probe is only meaningful when the sanitizer is active: it
# contains a deliberate heap overflow and must abort under instrumentation.
if(CRF_ENABLE_ASAN)
  add_executable(crf_asan_probe asan_probe.cpp)
  crf_enable_asan(crf_asan_probe)
  set_target_properties(crf_asan_probe PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
endif()

if(CRF_REGISTER_CTEST)
  enable_testing()
  add_test(NAME crf_tests COMMAND crf_tests)
endif()
