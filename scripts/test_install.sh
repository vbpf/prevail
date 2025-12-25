#!/bin/bash

# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

# Bash script to test prevail installation (Linux/macOS)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
INSTALL_DIR="$ROOT_DIR/test_install_output"
BUILD_DIR="$ROOT_DIR/build_install_test"
TEST_BUILD_DIR="$ROOT_DIR/examples/using_installed_package/build"

echo "==> Cleaning previous test artifacts..."
rm -rf "$INSTALL_DIR" "$BUILD_DIR" "$TEST_BUILD_DIR"

echo ""
echo "==> Building prevail..."
cmake -B "$BUILD_DIR" -S "$ROOT_DIR" -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
cmake --build "$BUILD_DIR" --config Release

echo ""
echo "==> Installing prevail to $INSTALL_DIR..."
cmake --install "$BUILD_DIR" --prefix "$INSTALL_DIR"

echo ""
echo "==> Building test consumer..."
cmake -B "$TEST_BUILD_DIR" -S "$ROOT_DIR/examples/using_installed_package" \
      -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
      -DCMAKE_BUILD_TYPE=Release
cmake --build "$TEST_BUILD_DIR" --config Release

echo ""
echo "==> Running test consumer..."
if [ -f "$TEST_BUILD_DIR/install_test" ]; then
  "$TEST_BUILD_DIR/install_test"
elif [ -f "$TEST_BUILD_DIR/Release/install_test" ]; then
  "$TEST_BUILD_DIR/Release/install_test"
else
  echo "ERROR: install_test binary not found"
  exit 1
fi

echo ""
echo "Installation test PASSED!"
echo "   - prevail built and installed successfully"
echo "   - find_package(prevail) works"
echo "   - Headers accessible"
echo "   - Dependencies resolved"
echo "   - Test program runs"

echo ""
echo "==> Cleaning up..."
rm -rf "$INSTALL_DIR" "$BUILD_DIR" "$TEST_BUILD_DIR"

echo "Done!"
