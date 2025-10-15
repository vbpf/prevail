# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# SetupYAMLCPP.cmake
#
# Ensures yaml-cpp::yaml-cpp target exists.
# First tries system package (CONFIG mode),
# otherwise fetches from upstream repository (headers only, no tools/tests).

if (NOT TARGET yaml-cpp::yaml-cpp)
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
      FIND_PACKAGE_ARGS NAMES yaml-cpp
    )
    FetchContent_MakeAvailable(yaml-cpp)

    if (NOT TARGET yaml-cpp::yaml-cpp AND TARGET yaml-cpp)
      add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
    endif ()
  endif ()

  message(STATUS "YAML-CPP target configured: yaml-cpp::yaml-cpp")
endif ()
