#!/bin/sh
# Host-side unit tests for the daemon's pure-C components.
# Usage: ./run.sh   (from this directory)
set -e
cd "$(dirname "$0")"
OUT="$(mktemp -d)"
clang -Wall -Wextra -I../net -o "$OUT/test_keepalive" test_keepalive_strategy.c ../net/SGKeepAliveStrategy.c
"$OUT/test_keepalive"
rm -rf "$OUT"
