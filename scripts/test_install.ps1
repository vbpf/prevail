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
# Pass the prefix with forward slashes: CMake interprets backslashes in a -D cache value
# as escapes (e.g. \t -> tab), which corrupts a Windows path like D:\a\...\test_install_output
# and makes find_package(prevail) miss the installed prevailConfig.cmake.
$InstallDirCMake = $InstallDir -replace '\\', '/'
$ConfigureArgs = @("-DCMAKE_PREFIX_PATH=$InstallDirCMake", "-DCMAKE_BUILD_TYPE=Release")

# On MSVC, prevail's public headers use Boost (the multiprecision Number/SafeI64 fallback),
# so the consumer needs Boost too -- both for the installed config's find_dependency(Boost)
# and to compile. Reuse the NuGet Boost headers the main build already provisioned under
# <build>/packages (SetupBoostHeaders.cmake) by pointing FindBoost at them.
if ($IsWindows -or $env:OS -match "Windows") {
    $BoostInc = Get-ChildItem -Path (Join-Path $BuildDir "packages") -Directory -Filter "boost*" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName "lib\native\include" } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($BoostInc) {
        Write-Host "    Using Boost headers for consumer: $BoostInc"
        $BoostIncCMake = $BoostInc -replace '\\', '/'
        # BOOST_INCLUDEDIR is FindBoost's documented include-path *hint*; Boost_INCLUDE_DIR is
        # its result variable. Set both so the header-only find_dependency(Boost) resolves.
        $ConfigureArgs += "-DBOOST_INCLUDEDIR=$BoostIncCMake"
        $ConfigureArgs += "-DBoost_INCLUDE_DIR=$BoostIncCMake"
    }
    else {
        # prevail's public headers need Boost on MSVC, so a missing Boost is fatal here --
        # fail with a clear message instead of letting the downstream configure error explain it.
        Write-Host "Boost headers not found under $BuildDir\packages; cannot build the consumer." -ForegroundColor Red
        exit 1
    }
}

cmake -B $TestBuildDir -S $ExampleDir @ConfigureArgs
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
