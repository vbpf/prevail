#!/usr/bin/env bash

# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

# Run Catch2 based tests in parallel using sharding.
# Any arguments passed to this script are forwarded to each test shard.

set -o errexit
set -o pipefail

root=$(git rev-parse --show-toplevel)
test_bin="${root}/tests"

if [[ ! -x "${test_bin}" ]]; then
    echo "Test executable not found: ${test_bin}" >&2
    exit 1
fi

jobs=${NUM_JOBS:-$(nproc)}

pids=()
for ((i=0; i<jobs; i++)); do
    "${test_bin}" --shard-count "${jobs}" --shard-index "${i}" "$@" &
    pids+=("$!")
done

trap 'kill "${pids[@]}"' INT TERM
ret=0
for pid in "${pids[@]}"; do
    wait "$pid" || ret=1
done
exit ${ret}
