# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
# Set cmake version to 3.16 to use CMP0091 aka MSVC_RUNTIME_LIBRARY property.
cmake_minimum_required(VERSION 3.16)
if (POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif ()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

project(prevail)

include(FetchContent)

if (EXISTS "${PROJECT_SOURCE_DIR}/.git" AND NOT CMAKE_CROSSCOMPILING)
    file(COPY scripts/pre-commit scripts/commit-msg DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
    option(VERIFIER_ENABLE_TESTS "Build tests" ON)
else ()
    option(VERIFIER_ENABLE_TESTS "Build tests" OFF)
endif ()

message("Building tests: ${VERIFIER_ENABLE_TESTS}")

FetchContent_Declare(GSL
        GIT_REPOSITORY "https://github.com/microsoft/GSL"
        GIT_TAG "v4.2.0"
        GIT_SHALLOW ON
)
FetchContent_MakeAvailable(GSL)

if (MSVC)
    set(BOOST_VERSION 1.87.0)
    find_package(Boost ${BOOST_VERSION} EXACT REQUIRED COMPONENTS process)

    if (VERIFIER_ENABLE_TESTS)
        set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/packages/yaml-cpp)
        include(ExternalProject)
        ExternalProject_Add(yaml-cpp
                GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
                GIT_TAG "0.8.0"
                GIT_SHALLOW true
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
                -DYAML_MSVC_SHARED_RT=ON
                -DYAML_CPP_BUILD_TESTS=OFF
                -DYAML_CPP_BUILD_TOOLS=OFF
                -DCMAKE_POLICY_VERSION_MINIMUM=3.14
        )
        set(YAML_CPP_LIBRARIES ${EXTERNAL_INSTALL_LOCATION}/lib/yaml-cpp$<$<CONFIG:DEBUG>:d>.lib)
        set(YAML_CPP_INCLUDE_DIR ${EXTERNAL_INSTALL_LOCATION}/include/)
    endif ()
else ()
    if (VERIFIER_ENABLE_TESTS)
        find_package(yaml-cpp REQUIRED)
    endif ()
    add_compile_definitions(BOOST_PROCESS_USE_STD_FS)
    add_library(Boost::process INTERFACE IMPORTED)
    target_include_directories(Boost::process INTERFACE ${Boost_INCLUDE_DIRS})
endif ()


file(GLOB LIB_SRC CONFIGURE_DEPENDS
        "./src/*.cpp"
        "./src/arith/*.cpp"
        "./src/cfg/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_utils/*.cpp"
        "./src/linux/gpl/spec_prototypes.cpp"
        "./src/linux/linux_platform.cpp"
)

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

add_library(prevail ${LIB_SRC})

target_include_directories(prevail PUBLIC
        ${CMAKE_SOURCE_DIR}/src
)
target_include_directories(prevail SYSTEM PUBLIC
        ${CMAKE_SOURCE_DIR}/external
        ${CMAKE_SOURCE_DIR}/external/bpf_conformance/external/elfio
        ${CMAKE_SOURCE_DIR}/external/libbtf
)

target_compile_options(prevail PRIVATE
        ${COMMON_FLAGS}
        "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>"
        "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>"
        "$<$<CONFIG:RELWITHDEBINFO>:${RELWITHDEBINFO_FLAGS}>"
        "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>"
)

add_subdirectory("external/bpf_conformance/external/elfio")
add_subdirectory("external/libbtf")
add_subdirectory("external/bpf_conformance/src")

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the prevail vcxproj file,
# so we force a constant GUID here.
set(prevail_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")
set(yaml-cpp_GUID_CMAKE "98d56b8a-d8eb-3d98-b8ee-c83696b4d58a" CACHE INTERNAL "Project GUID")

# Core libraries
target_link_libraries(prevail PRIVATE
        libbtf
        bpf_conformance
        Boost::process
)
target_link_libraries(prevail PUBLIC Microsoft.GSL::GSL)
set_target_properties(prevail PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)

# Main executables
add_executable(check src/main/check.cpp src/main/linux_verifier.cpp)
set_target_properties(check PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")
target_link_libraries(check PRIVATE prevail ${CMAKE_DL_LIBS})

# Tests
if (VERIFIER_ENABLE_TESTS)
    FetchContent_Declare(Catch2
            GIT_REPOSITORY "https://github.com/catchorg/Catch2.git"
            GIT_TAG "v3.11.0"
            GIT_SHALLOW ON
    )
    FetchContent_MakeAvailable(Catch2)

    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)

    set(ALL_TEST
            ${CMAKE_SOURCE_DIR}/src/test/test_conformance.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_join.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_marshal.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_print.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_sign_extension.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_subsumption.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_verify.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_wto.cpp
            ${CMAKE_SOURCE_DIR}/src/test/test_yaml.cpp
    )

    add_compile_definitions(YAML_CPP_STATIC_DEFINE)

    add_executable(tests ${ALL_TEST})
    add_executable(run_yaml src/test/run_yaml.cpp)
    add_executable(conformance_check src/test/conformance_check.cpp)

    add_library(ebpf_yaml_lib STATIC src/test/ebpf_yaml.cpp)
    target_link_libraries(ebpf_yaml_lib PRIVATE prevail yaml-cpp::yaml-cpp)

    foreach (tgt tests run_yaml conformance_check)
        set_target_properties(${tgt} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")
    endforeach ()

    target_link_libraries(tests PRIVATE prevail ebpf_yaml_lib Catch2::Catch2WithMain Threads::Threads yaml-cpp::yaml-cpp)
    target_link_libraries(run_yaml PRIVATE prevail ebpf_yaml_lib)
    target_link_libraries(conformance_check PRIVATE prevail ebpf_yaml_lib Threads::Threads)
endif ()
