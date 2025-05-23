# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
# Set cmake version to 3.16 to use CMP0091 aka MSVC_RUNTIME_LIBRARY property.
cmake_minimum_required(VERSION 3.16)
if (POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif ()

project(prevail)

include(FetchContent)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
    # Install Git pre-commit hook
    file(COPY scripts/pre-commit scripts/commit-msg
            DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
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
get_target_property(GSL_INCLUDE_DIRS Microsoft.GSL::GSL INTERFACE_INCLUDE_DIRECTORIES)

if (VERIFIER_ENABLE_TESTS)
    FetchContent_Declare(Catch2
            GIT_REPOSITORY "https://github.com/catchorg/Catch2.git"
            GIT_TAG "v3.8.1"
            GIT_SHALLOW ON
    )
    FetchContent_MakeAvailable(Catch2)
endif ()


if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
        "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    if (VERIFIER_ENABLE_TESTS)
        find_package(yaml-cpp REQUIRED)
    endif ()
    find_package(Boost REQUIRED)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    list(APPEND CMAKE_CONFIGURATION_TYPES FuzzerDebug)
    list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
            "Add the configurations that we need"
            FORCE)
    set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
    set(CMAKE_SHARED_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
    set(CMAKE_C_FLAGS_FUZZERDEBUG "${CMAKE_C_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")
    set(CMAKE_CXX_FLAGS_FUZZERDEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address /fsanitize=fuzzer /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")

    find_program(NUGET nuget)
    if (NOT NUGET)
        message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
    else ()
        execute_process(COMMAND ${NUGET} install "Boost" -Version 1.81.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
        set(BOOST_VERSION 1.81.0)
    endif ()
    set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
    set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc143/lib/native)

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
endif ()

include_directories(./external)
include_directories(./external/bpf_conformance/external/elfio)
include_directories(./src)
include_directories(./external/libbtf)
include_directories(${GSL_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${YAML_CPP_INCLUDE_DIR})

link_directories(${YAML_CPP_LIBRARY_DIR})
link_directories(${Boost_LIBRARY_DIRS})


file(GLOB LIB_SRC
        "./src/*.cpp"
        "./src/arith/*.cpp"
        "./src/cfg/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_utils/*.cpp"
        "./src/linux/gpl/spec_prototypes.cpp"
        "./src/linux/linux_platform.cpp"
)

if (VERIFIER_ENABLE_TESTS)
    file(GLOB ALL_TEST
            "./src/test/test_conformance.cpp"
            "./src/test/test_marshal.cpp"
            "./src/test/test_print.cpp"
            "./src/test/test_verify.cpp"
            "./src/test/test_wto.cpp"
            "./src/test/test_yaml.cpp"
            "./src/test/test_sign_extension.cpp"
    )

    set(LIB_SRC ${LIB_SRC} "./src/test/ebpf_yaml.cpp")
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
        "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)

    set(RELEASE_FLAGS -O2 -flto=auto -ffat-lto-objects)

    set(DEBUG_FLAGS -O0 -g3 -fno-omit-frame-pointer)

    set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20")
endif ()

add_library(prevail ${LIB_SRC})
target_compile_definitions(prevail PRIVATE YAML_CPP_STATIC_DEFINE)

if (VERIFIER_ENABLE_TESTS)
    add_executable(check src/main/check.cpp src/main/linux_verifier.cpp)
    add_executable(tests ${ALL_TEST})
    add_executable(run_yaml src/main/run_yaml.cpp)
    add_executable(conformance_check src/test/conformance_check.cpp)
endif ()

target_include_directories(prevail PRIVATE ${GSL_INCLUDE_DIRS})

if (VERIFIER_ENABLE_TESTS)
    target_include_directories(run_yaml PRIVATE src/test)

    set_target_properties(check
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

    set_target_properties(tests
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

    set_target_properties(run_yaml
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

    set_target_properties(conformance_check
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

    add_dependencies(tests conformance_check)
endif ()

target_compile_options(prevail PRIVATE ${COMMON_FLAGS})
target_compile_options(prevail PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(prevail PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(prevail PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

add_subdirectory("external/bpf_conformance/external/elfio")
if (VERIFIER_ENABLE_TESTS)
    add_subdirectory("external/bpf_conformance/src")
endif ()
add_subdirectory("external/libbtf")

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the prevail vcxproj file,
# so we force a constant GUID here.
set(prevail_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")
set(yaml-cpp_GUID_CMAKE "98d56b8a-d8eb-3d98-b8ee-c83696b4d58a" CACHE INTERNAL "Project GUID")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(prevail PRIVATE ${YAML_CPP_LIBRARIES})
target_link_libraries(prevail PRIVATE libbtf)
target_link_libraries(prevail PRIVATE Microsoft.GSL::GSL)
target_compile_options(prevail PRIVATE ${COMMON_FLAGS})

if (VERIFIER_ENABLE_TESTS)
    target_compile_options(check PRIVATE ${COMMON_FLAGS})
    target_compile_options(check PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
    target_compile_options(check PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
    target_compile_options(check PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
    target_link_libraries(check PRIVATE prevail)

    message("Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
    target_compile_options(tests PRIVATE ${COMMON_FLAGS})
    target_compile_options(tests PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
    target_compile_options(tests PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
    target_compile_options(tests PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
    target_link_libraries(tests PRIVATE prevail)
    target_link_libraries(tests PRIVATE bpf_conformance)
    target_link_libraries(tests PRIVATE ${CMAKE_DL_LIBS})
    target_link_libraries(tests PRIVATE Threads::Threads)
    target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)

    target_link_libraries(run_yaml PRIVATE prevail)

    target_link_libraries(conformance_check PRIVATE prevail)
endif ()
