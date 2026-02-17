# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.24)
if (POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif ()
if (NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif ()

project(prevail VERSION 0.1.2)

# NOTE: Do not use CMAKE_SOURCE_DIR in this project.
# When prevail is consumed via add_subdirectory()/FetchContent, CMAKE_SOURCE_DIR refers to
# the top-level superproject, not prevail's root.
set(prevail_source_dir "${PROJECT_SOURCE_DIR}")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

include(FetchContent)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git" AND NOT CMAKE_CROSSCOMPILING)
  file(COPY "${prevail_source_dir}/scripts/pre-commit" "${prevail_source_dir}/scripts/commit-msg" DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
  option(prevail_ENABLE_TESTS "Build tests" ON)
else ()
  option(prevail_ENABLE_TESTS "Build tests" OFF)
endif ()

message("Building tests: ${prevail_ENABLE_TESTS}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
  "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(COMMON_FLAGS -Wall -Wfatal-errors)

  include(CheckTypeSize)
  check_type_size("void*" SIZEOF_VOID_P)
  check_type_size("long" SIZEOF_LONG)
  add_compile_definitions(SIZEOF_VOID_P=${SIZEOF_VOID_P} SIZEOF_LONG=${SIZEOF_LONG})

  set(RELEASE_FLAGS -O2 -flto=auto)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported)
  if (ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif ()

  set(RELWITHDEBINFO_FLAGS ${RELEASE_FLAGS} -g3)
  set(DEBUG_FLAGS -O0 -g3 -fno-omit-frame-pointer)

  set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
endif ()

if (MSVC)
  # Silence Windows version warnings
  add_compile_definitions(_WIN32_WINNT=0x0A00)
  # Add FuzzerDebug configuration (MSVC Address/Fuzzer sanitizer build)
  list(APPEND CMAKE_CONFIGURATION_TYPES FuzzerDebug)
  list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
    "Add the configurations that we need" FORCE)

  # Derive base debug flags and add sanitizer instrumentation
  set(CMAKE_C_FLAGS_FUZZERDEBUG "${CMAKE_C_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")

  set(CMAKE_CXX_FLAGS_FUZZERDEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")

  # Propagate linker flags (same as Debug)
  set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
  set(CMAKE_SHARED_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
endif ()

FetchContent_Declare(GSL
  GIT_REPOSITORY "https://github.com/microsoft/GSL"
  GIT_TAG "v4.2.0"
  GIT_SHALLOW ON
)
set(GSL_INSTALL ON CACHE BOOL "Force GSL install to vendor it with prevail" FORCE)
set(GSL_TEST OFF CACHE BOOL "Skip GSL tests when building as a dependency" FORCE)
FetchContent_MakeAvailable(GSL)

if (prevail_ENABLE_TESTS)
  include(cmake/SetupYAMLCPP.cmake)
endif ()

# Add elfio before bpf_conformance_core so it can detect and use it
add_subdirectory("${prevail_source_dir}/external/bpf_conformance/external/elfio" "${CMAKE_CURRENT_BINARY_DIR}/elfio")

# Use only the core library from bpf_conformance (pure C++20, no Boost dependency)
add_subdirectory("${prevail_source_dir}/external/bpf_conformance/lib" "${CMAKE_CURRENT_BINARY_DIR}/bpf_conformance_core")

include(cmake/SetupBoostHeaders.cmake)

# Escape regex metacharacters in prevail_source_dir for use in list(FILTER ... REGEX ...)
string(REGEX REPLACE "([][+.*()^$?|\\\\])" "\\\\\\1" prevail_source_dir_escaped "${prevail_source_dir}")

file(GLOB_RECURSE prevail_LIB_SRC CONFIGURE_DEPENDS "${prevail_source_dir}/src/*.cpp")
list(FILTER prevail_LIB_SRC EXCLUDE REGEX "${prevail_source_dir_escaped}/src/main/.*")
list(FILTER prevail_LIB_SRC EXCLUDE REGEX "${prevail_source_dir_escaped}/src/test/.*")

add_library(prevail ${prevail_LIB_SRC})
# 1. Standard library include paths
target_include_directories(prevail PUBLIC
  $<BUILD_INTERFACE:${prevail_source_dir}/src>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# 2. Consolidated Target Include Directories (Interface)
# We use SYSTEM to suppress warnings from external headers
target_include_directories(prevail SYSTEM PUBLIC
  # Local build tree paths
  $<BUILD_INTERFACE:${prevail_source_dir}/external>
  $<BUILD_INTERFACE:${prevail_source_dir}/external/bpf_conformance/external/elfio>
  $<BUILD_INTERFACE:${prevail_source_dir}/external/bpf_conformance/lib/include>
  $<BUILD_INTERFACE:${prevail_source_dir}/external/libbtf>
  $<BUILD_INTERFACE:${Boost_INCLUDE_DIR}>

  # Install tree paths
  # All dependencies (bpf_conformance_core, elfio, libbtf, prevail) are rooted in include/
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# 3. Installation Directives
# Ensure bpf_conformance_core is reachable via <bpf_conformance_core/...>
install(DIRECTORY "${prevail_source_dir}/external/bpf_conformance/lib/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# Ensure elfio is reachable via <elfio/...>
install(DIRECTORY "${prevail_source_dir}/external/bpf_conformance/external/elfio/elfio/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/elfio"
  FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

# Ensure libbtf is reachable via <libbtf/...>
# Note: Use the nested libbtf/ directory to match the include namespace
install(DIRECTORY "${prevail_source_dir}/external/libbtf/libbtf/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/libbtf"
  FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

option(ENABLE_ASAN "Enable AddressSanitizer if supported" OFF)

target_compile_options(prevail PRIVATE
  ${COMMON_FLAGS}
  "$<$<CONFIG:Debug>:${DEBUG_FLAGS}>"
  "$<$<CONFIG:Release>:${RELEASE_FLAGS}>"
  "$<$<CONFIG:RelWithDebInfo>:${RELWITHDEBINFO_FLAGS}>"
  "$<$<BOOL:${ENABLE_ASAN}>:${SANITIZE_FLAGS}>"
)

add_subdirectory("${prevail_source_dir}/external/libbtf" "${CMAKE_CURRENT_BINARY_DIR}/libbtf")
target_include_directories(libbtf INTERFACE
  $<BUILD_INTERFACE:${prevail_source_dir}/external/libbtf/libbtf>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/libbtf>
)

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the prevail vcxproj file,
# so we force a constant GUID here.
set(prevail_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")
set(yaml-cpp_GUID_CMAKE "98d56b8a-d8eb-3d98-b8ee-c83696b4d58a" CACHE INTERNAL "Project GUID")

# Core libraries
target_link_libraries(prevail PUBLIC libbtf Microsoft.GSL::GSL)
if (TARGET Boost::headers)
  target_link_libraries(prevail PUBLIC Boost::headers)
endif ()
set_target_properties(prevail PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES)

set(prevail_binary_dir "${prevail_source_dir}/bin" CACHE INTERNAL "")

# Main executables
add_executable(check "${prevail_source_dir}/src/main/check.cpp" "${prevail_source_dir}/src/main/linux_verifier.cpp")
target_link_libraries(check PRIVATE prevail ${CMAKE_DL_LIBS})
if (CMAKE_CONFIGURATION_TYPES)
  set_target_properties(check PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${prevail_binary_dir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${prevail_binary_dir}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${prevail_binary_dir}"
  )
else ()
  set_target_properties(check PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${prevail_binary_dir}")
endif ()

# Tests
if (prevail_ENABLE_TESTS)
  FetchContent_Declare(Catch2
    GIT_REPOSITORY "https://github.com/catchorg/Catch2.git"
    GIT_TAG "v3.13.0"
    GIT_SHALLOW ON
  )
  FetchContent_MakeAvailable(Catch2)

  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  add_executable(run_yaml "${prevail_source_dir}/src/test/run_yaml.cpp")

  file(GLOB prevail_TEST_SRC CONFIGURE_DEPENDS "${prevail_source_dir}/src/test/test_*.cpp")
  add_executable(tests ${prevail_TEST_SRC})

  add_library(ebpf_yaml_lib STATIC "${prevail_source_dir}/src/test/ebpf_yaml.cpp")
  target_link_libraries(ebpf_yaml_lib PRIVATE prevail bpf_conformance_core yaml-cpp::yaml-cpp)

  target_link_libraries(run_yaml PRIVATE prevail ebpf_yaml_lib)

  target_link_libraries(tests PRIVATE prevail ebpf_yaml_lib bpf_conformance_core Catch2::Catch2WithMain Threads::Threads yaml-cpp::yaml-cpp)

  if (CMAKE_CONFIGURATION_TYPES)
    set_target_properties(tests run_yaml PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY_DEBUG "${prevail_binary_dir}"
      RUNTIME_OUTPUT_DIRECTORY_RELEASE "${prevail_binary_dir}"
      RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${prevail_binary_dir}"
    )
  else ()
    set_target_properties(tests run_yaml PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY ${prevail_binary_dir})
  endif ()
endif ()

# Installation
set(prevail_config_dir "${CMAKE_INSTALL_LIBDIR}/cmake/prevail")

# Create convenience header: #include <prevail.hpp>
# This redirects to prevail/ebpf_verifier.hpp which provides core functionality
set(prevail_redirect_header "${CMAKE_CURRENT_BINARY_DIR}/prevail.hpp")
file(WRITE "${prevail_redirect_header}" "#pragma once\n#include <prevail/ebpf_verifier.hpp>\n")

install(TARGETS prevail libbtf GSL
  EXPORT prevailTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY "${prevail_source_dir}/src/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/prevail"
  FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
  PATTERN "main/*" EXCLUDE
  PATTERN "test/*" EXCLUDE
)

# Install convenience header to top-level include/
# This allows: #include <prevail.hpp>
# While specific headers use: #include <prevail/arith/linear_constraint.hpp>
install(FILES "${prevail_redirect_header}"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(EXPORT prevailTargets
  FILE prevailTargets.cmake
  NAMESPACE prevail::
  DESTINATION "${prevail_config_dir}"
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/prevailConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
  "${prevail_source_dir}/cmake/prevailConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/prevailConfig.cmake"
  INSTALL_DESTINATION "${prevail_config_dir}"
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/prevailConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/prevailConfigVersion.cmake"
  DESTINATION "${prevail_config_dir}"
)
