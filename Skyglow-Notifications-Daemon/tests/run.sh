#!/bin/sh
# Host-side unit tests for the daemon's pure-C components.
# Usage: ./run.sh   (from this directory)
set -e
cd "$(dirname "$0")"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

clang -Wall -Wextra -I../net -o "$OUT/test_keepalive" test_keepalive_strategy.c ../net/SGKeepAliveStrategy.c
"$OUT/test_keepalive"

clang -Wall -Wextra -I../core -I../shared -o "$OUT/test_connection_policy" \
    test_connection_policy.c ../core/SGConnectionPolicy.c
"$OUT/test_connection_policy"
