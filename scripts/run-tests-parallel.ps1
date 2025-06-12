# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

# Run Catch2 based tests in parallel using sharding.
# Any arguments passed to this script are forwarded to each test shard.

$ErrorActionPreference = 'Stop'

$root = (git rev-parse --show-toplevel).Trim()
$testBin = Join-Path $root "$env:BUILD_CONFIGURATION\tests.exe"

if (-not (Test-Path $testBin)) {
    Write-Error "Test executable not found: $testBin"
    exit 1
}

$jobs = [int](if ($env:NUM_JOBS) { $env:NUM_JOBS } else { [Environment]::ProcessorCount })

$procs = @()
for ($i = 0; $i -lt $jobs; $i++) {
    $arguments = "--shard-count $jobs --shard-index $i" + (if ($args) { ' ' + ($args -join ' ') } else { '' })
    $procs += Start-Process -FilePath $testBin -ArgumentList $arguments -NoNewWindow -PassThru
}

$exitCode = 0
foreach ($p in $procs) {
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { $exitCode = $p.ExitCode }
}
exit $exitCode
