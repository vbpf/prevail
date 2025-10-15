# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.24)
if (POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif ()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

project(prevail)

include(FetchContent)

if (EXISTS "${PROJECT_SOURCE_DIR}/.git" AND NOT CMAKE_CROSSCOMPILING)
  file(COPY "${CMAKE_SOURCE_DIR}/scripts/pre-commit" "${CMAKE_SOURCE_DIR}/scripts/commit-msg" DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
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

FetchContent_Declare(GSL
  GIT_REPOSITORY "https://github.com/microsoft/GSL"
  GIT_TAG "v4.2.0"
  GIT_SHALLOW ON
)
FetchContent_MakeAvailable(GSL)

if (prevail_ENABLE_TESTS)
  find_package(yaml-cpp CONFIG QUIET)

  if (NOT yaml-cpp_FOUND)
    include(FetchContent)

    set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(yaml-cpp
      GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
      GIT_TAG 0.8.0
      GIT_SHALLOW TRUE
      FIND_PACKAGE_ARGS NAMES yaml-cpp # enables find_package fallback within FC
    )
    FetchContent_MakeAvailable(yaml-cpp)

    # yaml-cpp defines target 'yaml-cpp'; provide the standard alias if missing
    if (NOT TARGET yaml-cpp::yaml-cpp AND TARGET yaml-cpp)
      add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
    endif ()
  endif ()
endif ()

add_compile_definitions(BOOST_PROCESS_USE_STD_FS)
if (MSVC)
  set(BOOST_HEADERS_ROOT "${CMAKE_BINARY_DIR}/packages/boost/lib/native")

  add_library(Boost::headers INTERFACE IMPORTED)
  target_include_directories(Boost::headers INTERFACE "${BOOST_HEADERS_ROOT}/include")

  if (prevail_ENABLE_TESTS)
    add_library(Boost::process INTERFACE IMPORTED)
    target_link_libraries(Boost::process INTERFACE Boost::headers)
  endif ()

  # Silence Windows version warnings
  add_compile_definitions(_WIN32_WINNT=0x0A00)
else ()
  if (prevail_ENABLE_TESTS)
    add_library(Boost::process INTERFACE IMPORTED)
    target_include_directories(Boost::process INTERFACE ${Boost_INCLUDE_DIRS})
  endif ()
endif ()

if (MSVC)
  # Add FuzzerDebug configuration (MSVC Address/Fuzzer sanitizer build)
  list(APPEND CMAKE_CONFIGURATION_TYPES FuzzerDebug)
  list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
    "Add the configurations that we need" FORCE)

  # Derive base debug flags and add sanitizer instrumentation
  set(CMAKE_C_FLAGS_FUZZERDEBUG
    "${CMAKE_C_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer "
    "/fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge "
    "/fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div "
    "/ZH:SHA_256")

  set(CMAKE_CXX_FLAGS_FUZZERDEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer "
    "/fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge "
    "/fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div "
    "/ZH:SHA_256")

  # Propagate linker flags (same as Debug)
  set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
  set(CMAKE_SHARED_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
endif ()

file(GLOB_RECURSE prevail_LIB_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")
list(FILTER prevail_LIB_SRC EXCLUDE REGEX "${CMAKE_SOURCE_DIR}/src/main/.*")
list(FILTER prevail_LIB_SRC EXCLUDE REGEX "${CMAKE_SOURCE_DIR}/src/test/.*")

add_library(prevail ${prevail_LIB_SRC})

target_include_directories(prevail PUBLIC
  ${CMAKE_SOURCE_DIR}/src
)
target_include_directories(prevail SYSTEM PUBLIC
  "${CMAKE_SOURCE_DIR}/external"
  "${CMAKE_SOURCE_DIR}/external/bpf_conformance/external/elfio"
  "${CMAKE_SOURCE_DIR}/external/libbtf"
  "${Boost_INCLUDE_DIR}"
)

target_compile_options(prevail PRIVATE
  ${COMMON_FLAGS}
  "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>"
  "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>"
  "$<$<CONFIG:RELWITHDEBINFO>:${RELWITHDEBINFO_FLAGS}>"
  "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>"
)

add_subdirectory("${CMAKE_SOURCE_DIR}/external/bpf_conformance/external/elfio")
if (prevail_ENABLE_TESTS)
  add_subdirectory("${CMAKE_SOURCE_DIR}/external/bpf_conformance/src")
endif ()
add_subdirectory("${CMAKE_SOURCE_DIR}/external/libbtf")

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the prevail vcxproj file,
# so we force a constant GUID here.
set(prevail_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")
set(yaml-cpp_GUID_CMAKE "98d56b8a-d8eb-3d98-b8ee-c83696b4d58a" CACHE INTERNAL "Project GUID")

# Core libraries
target_link_libraries(prevail PRIVATE libbtf)
target_link_libraries(prevail PUBLIC Microsoft.GSL::GSL)
if (TARGET Boost::headers)
  target_link_libraries(prevail PUBLIC Boost::headers)
endif ()
set_target_properties(prevail PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES)

set(prevail_binary_dir "${CMAKE_SOURCE_DIR}/bin" CACHE INTERNAL "")

# Main executables
add_executable(check "${CMAKE_SOURCE_DIR}/src/main/check.cpp" "${CMAKE_SOURCE_DIR}/src/main/linux_verifier.cpp")
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
    GIT_TAG "v3.11.0"
    GIT_SHALLOW ON
  )
  FetchContent_MakeAvailable(Catch2)

  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)

  add_executable(run_yaml "${CMAKE_SOURCE_DIR}/src/test/run_yaml.cpp")
  add_executable(conformance_check "${CMAKE_SOURCE_DIR}/src/test/conformance_check.cpp")

  file(GLOB prevail_TEST_SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/test/test_*.cpp")
  add_executable(tests ${prevail_TEST_SRC})

  add_library(ebpf_yaml_lib STATIC "${CMAKE_SOURCE_DIR}/src/test/ebpf_yaml.cpp")
  target_link_libraries(ebpf_yaml_lib PRIVATE prevail bpf_conformance yaml-cpp::yaml-cpp)

  target_link_libraries(run_yaml PRIVATE prevail ebpf_yaml_lib)
  target_link_libraries(conformance_check PRIVATE prevail ebpf_yaml_lib Boost::process Threads::Threads)
  target_link_libraries(tests PRIVATE prevail ebpf_yaml_lib Catch2::Catch2WithMain Threads::Threads yaml-cpp::yaml-cpp)

  if (CMAKE_CONFIGURATION_TYPES)
    set_target_properties(tests run_yaml conformance_check PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY_DEBUG "${prevail_binary_dir}"
      RUNTIME_OUTPUT_DIRECTORY_RELEASE "${prevail_binary_dir}"
      RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${prevail_binary_dir}"
    )
  else ()
    set_target_properties(tests run_yaml conformance_check PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY ${prevail_binary_dir})
  endif ()

  # conformance tests use the conformance_check binary; ensure it's built first,
  # and pass its path via a define
  add_dependencies(tests conformance_check)
  target_compile_definitions(tests PRIVATE
    CONFORMANCE_CHECK_PATH="$<TARGET_FILE:conformance_check>"
  )
endif ()
