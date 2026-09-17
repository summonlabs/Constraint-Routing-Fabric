cmake_minimum_required(VERSION 3.25)
project(ConstraintRoutingFabricConsumer CXX)

# An independent consumer of the installed package. This project is intentionally
# not part of the library build and never references the library source tree.
find_package(ConstraintRoutingFabric CONFIG REQUIRED)

add_executable(crf_consumer main.cpp)
target_link_libraries(crf_consumer PRIVATE SummonSoftwareLabs::ConstraintRoutingFabric)
set_target_properties(crf_consumer PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(crf_consumer PRIVATE /W4 /WX /permissive- /utf-8)
endif()
