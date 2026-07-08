# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.24)
if (POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif ()
if (NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif ()

project(prevail VERSION 0.2.5)

# NOTE: Do not use CMAKE_SOURCE_DIR in this project.
# When prevail is consumed via add_subdirectory()/FetchContent, CMAKE_SOURCE_DIR refers to
# the top-level superproject, not prevail's root.
set(prevail_source_dir "${PROJECT_SOURCE_DIR}")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

include(FetchContent)

# Accept both a `.git` directory (normal clone) and a `.git` file (linked
# worktrees, submodules) so tests are enabled in worktrees too.
if (EXISTS "${PROJECT_SOURCE_DIR}/.git" AND NOT CMAKE_CROSSCOMPILING)
  option(prevail_ENABLE_TESTS "Build tests" ON)
  # Only a normal clone has a `.git` directory to install hooks into. In a linked
  # worktree (or submodule) `.git` is a file, so copying to `.git/hooks` would fail
  # configure with "Not a directory"; worktrees inherit the hooks from the main clone.
  if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
    file(COPY "${prevail_source_dir}/scripts/pre-commit" "${prevail_source_dir}/scripts/commit-msg" DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
  endif ()
else ()
  option(prevail_ENABLE_TESTS "Build tests" OFF)
endif ()

message("Building tests: ${prevail_ENABLE_TESTS}")

set(CMAKE_CXX_STANDARD 23)
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
  set(SANITIZE_LINK_FLAGS -fsanitize=address)
endif ()

if (MSVC)
  # Silence Windows version warnings
  add_compile_definitions(_WIN32_WINNT=0x0A00)
  # AddressSanitizer flags (MSVC injects the ASan runtime automatically at link time).
  set(SANITIZE_FLAGS /fsanitize=address)
  set(SANITIZE_LINK_FLAGS "")
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

set(prevail_LIB_SRC
  src/cfg/wto.cpp
  src/crab/array_domain.cpp
  src/crab/bitset_domain.cpp
  src/crab/ebpf_checker.cpp
  src/crab/ebpf_domain.cpp
  src/crab/ebpf_transformer.cpp
  src/crab/finite_domain.cpp
  src/crab/interval.cpp
  src/crab/region_semantics.cpp
  src/crab/splitdbm/split_dbm.cpp
  src/crab/type_domain.cpp
  src/crab/type_to_num.cpp
  src/crab/var_registry.cpp
  src/crab/zone_domain.cpp
  src/crab_utils/debug.cpp
  src/crab/extrapolator.cpp
  src/fwd_analyzer.cpp
  src/io/elf_core_reloc.cpp
  src/io/elf_extern_resolve.cpp
  src/io/elf_loader.cpp
  src/io/elf_map_parser.cpp
  src/io/elf_reader.cpp
  src/ir/assertions.cpp
  src/ir/call_resolver.cpp
  src/ir/cfg_builder.cpp
  src/ir/unmarshal.cpp
  src/linux/gpl/spec_prototypes.cpp
  src/linux/kfunc.cpp
  src/linux/linux_platform.cpp
  src/printing.cpp
  src/result.cpp
  src/string_constraints.cpp
)
list(TRANSFORM prevail_LIB_SRC PREPEND "${prevail_source_dir}/")

add_library(prevail ${prevail_LIB_SRC})
# 1. Standard library include paths
target_include_directories(prevail PUBLIC
  $<BUILD_INTERFACE:${prevail_source_dir}/src>
  # <prevail/...> and the <prevail.hpp> redirect resolve against include/.
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  # prevail's own headers use src-relative includes ("crab_utils/...", "io/...") and are
  # installed under include/prevail/, so that directory must be on the consumer's path too.
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/prevail>
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
)

# Export the C++ standard as a usage requirement so consumers of the installed
# package are compiled with the right -std.
target_compile_features(prevail PUBLIC cxx_std_20)

if (ENABLE_ASAN)
  # Apply AddressSanitizer as a usage requirement (PUBLIC) so the CLI, tests, and
  # any consumer linking `prevail` are both instrumented and linked consistently.
  message(STATUS "AddressSanitizer enabled (ENABLE_ASAN=ON)")
  target_compile_options(prevail PUBLIC ${SANITIZE_FLAGS})
  if (NOT MSVC)
    # GCC/Clang need -fsanitize=address at link time too; MSVC injects it automatically.
    target_link_options(prevail PUBLIC ${SANITIZE_LINK_FLAGS})
  endif ()
endif ()

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
# Track whether prevail's public interface actually links a Boost imported target, so the
# installed package's find dependency matches: a consumer must resolve Boost iff we built
# against it. On the MSVC/NuGet-headers path there is no Boost::headers target, so the
# installed config must not hard-require a Boost CMake package that does not exist there.
if (TARGET Boost::headers)
  target_link_libraries(prevail PUBLIC Boost::headers)
  set(prevail_PUBLIC_NEEDS_BOOST TRUE)
else ()
  set(prevail_PUBLIC_NEEDS_BOOST FALSE)
endif ()
set_target_properties(prevail PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES)

set(prevail_binary_dir "${prevail_source_dir}/bin" CACHE INTERNAL "")

# Version string baked into the CLI (`prevail --version`).
# Prefer `git describe` so non-release builds are unambiguous; fall back to the
# project version when building outside a git checkout (e.g. tarball or install).
set(prevail_VERSION_STRING "")
# Accept both a `.git` directory (normal clone) and a `.git` file (linked
# worktrees, submodules) — both are valid Git layouts that resolve under
# `git -C`.
if (EXISTS "${prevail_source_dir}/.git" AND NOT CMAKE_CROSSCOMPILING)
  find_package(Git QUIET)
  if (GIT_FOUND)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${prevail_source_dir}" describe --tags --always --dirty
      OUTPUT_VARIABLE prevail_VERSION_STRING
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
  endif ()
endif ()
if (prevail_VERSION_STRING STREQUAL "")
  set(prevail_VERSION_STRING "v${PROJECT_VERSION}")
endif ()

# Main executable: bin/prevail
add_executable(prevail-cli "${prevail_source_dir}/src/main.cpp")
set_target_properties(prevail-cli PROPERTIES OUTPUT_NAME "prevail")
target_link_libraries(prevail-cli PRIVATE prevail ${CMAKE_DL_LIBS})
target_compile_definitions(prevail-cli PRIVATE PREVAIL_VERSION_STRING="${prevail_VERSION_STRING}")
if (CMAKE_CONFIGURATION_TYPES)
  set_target_properties(prevail-cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${prevail_binary_dir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${prevail_binary_dir}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${prevail_binary_dir}"
  )
else ()
  set_target_properties(prevail-cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${prevail_binary_dir}")
endif ()

# Tests
if (prevail_ENABLE_TESTS)
  FetchContent_Declare(Catch2
    GIT_REPOSITORY "https://github.com/catchorg/Catch2.git"
    GIT_TAG "v3.14.0"
    GIT_SHALLOW ON
  )
  FetchContent_MakeAvailable(Catch2)

  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  add_executable(run_yaml "${prevail_source_dir}/src/test/run_yaml.cpp")

  set(prevail_TEST_SRC
    src/test/test_array_domain.cpp
    src/test/test_cfg_builder_passes.cpp
    src/test/test_conformance.cpp
    src/test/test_elf_loader.cpp
    src/test/test_failure_slice.cpp
    src/test/test_int128.cpp
    src/test/test_interval_bitwise.cpp
    src/test/test_join.cpp
    src/test/test_marshal.cpp
    src/test/test_platform_tables.cpp
    src/test/test_print.cpp
    src/test/test_runtime_config.cpp
    src/test/test_sign_extension.cpp
    src/test/test_subsumption.cpp
    src/test/test_type_domain.cpp
    src/test/test_type_to_num.cpp
    src/test/test_verify_bcc.cpp
    src/test/test_verify_bpf_cilium_test.cpp
    src/test/test_verify_build.cpp
    src/test/test_verify_cilium.cpp
    src/test/test_verify_cilium_core.cpp
    src/test/test_verify_cilium_ebpf.cpp
    src/test/test_verify_cilium_examples.cpp
    src/test/test_verify_falco.cpp
    src/test/test_verify_invalid.cpp
    src/test/test_verify_katran.cpp
    src/test/test_verify_libbpf_bootstrap.cpp
    src/test/test_verify_linux.cpp
    src/test/test_verify_linux_selftests.cpp
    src/test/test_verify_multithreading.cpp
    src/test/test_verify_new_linux.cpp
    src/test/test_verify_ovs.cpp
    src/test/test_verify_prototype_kernel.cpp
    src/test/test_verify_suricata.cpp
    src/test/test_wto.cpp
    src/test/test_yaml.cpp
  )
  list(TRANSFORM prevail_TEST_SRC PREPEND "${prevail_source_dir}/")
  add_executable(tests ${prevail_TEST_SRC}
    "${prevail_source_dir}/src/test/setup_msvc_debug.cpp"
  )

  add_library(ebpf_yaml_lib STATIC
    "${prevail_source_dir}/src/test/ebpf_yaml.cpp"
    "${prevail_source_dir}/src/test/marshal.cpp"
    "${prevail_source_dir}/src/test/parse.cpp"
  )
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
