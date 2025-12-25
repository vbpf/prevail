# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

# PowerShell script to test prevail installation
# For Windows, Linux, and macOS

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $RootDir "test_install_output"
$BuildDir = Join-Path $RootDir "build_install_test"
$TestBuildDir = Join-Path $RootDir "examples\using_installed_package\build"

Write-Host "==> Cleaning previous test artifacts..." -ForegroundColor Cyan
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $TestBuildDir -ErrorAction SilentlyContinue

Write-Host "`n==> Building prevail..." -ForegroundColor Cyan
cmake -B $BuildDir -S $RootDir -DCMAKE_BUILD_TYPE=Release -Dprevail_ENABLE_TESTS=OFF
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $BuildDir --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n==> Installing prevail to $InstallDir..." -ForegroundColor Cyan
cmake --install $BuildDir --prefix $InstallDir --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n==> Building test consumer..." -ForegroundColor Cyan
$ExampleDir = Join-Path $RootDir "examples\using_installed_package"
cmake -B $TestBuildDir -S $ExampleDir -DCMAKE_PREFIX_PATH=$InstallDir -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $TestBuildDir --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n==> Running test consumer..." -ForegroundColor Cyan
$TestExe = if ($IsWindows -or $env:OS -match "Windows") {
    Join-Path $TestBuildDir "Release\install_test.exe"
} else {
    Join-Path $TestBuildDir "install_test"
}

& $TestExe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nInstallation test PASSED!" -ForegroundColor Green
Write-Host "   - prevail built and installed successfully"
Write-Host "   - find_package(prevail) works"
Write-Host "   - Headers accessible"
Write-Host "   - Dependencies resolved"
Write-Host "   - Test program runs"

Write-Host "`n==> Cleaning up..." -ForegroundColor Cyan
Remove-Item -Recurse -Force $InstallDir
Remove-Item -Recurse -Force $BuildDir
Remove-Item -Recurse -Force $TestBuildDir

Write-Host "Done!" -ForegroundColor Green
