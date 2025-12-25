# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

# Test consumer project that uses installed prevail
cmake_minimum_required(VERSION 3.24)
project(prevail_install_test)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# This will fail if prevail wasn't installed correctly
find_package(prevail 0.1.0 REQUIRED)

add_executable(install_test main.cpp)
target_link_libraries(install_test PRIVATE prevail::prevail)

# Add test
enable_testing()
add_test(NAME install_smoke_test COMMAND install_test)
