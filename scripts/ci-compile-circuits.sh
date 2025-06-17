#!/bin/bash

# This script compiles a subset of Noir circuits required for CI pipeline.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)

# Generate unconstrained circuits, so that we can test the circuit logic
# for given inputs without doing fully constrained proving
./node_modules/.bin/tsx src/ts/scripts/circuit-builder.ts generate unconstrained

# Circuits list provided by ci-circuits.sh
mapfile -t CIRCUITS < "$ROOT/scripts/helpers/ci-circuits.txt"

echo "Circuits: ${CIRCUITS[@]}"

# Format generated files
echo "Formatting generated files"
nargo fmt

for circuit in "${CIRCUITS[@]}"; do
    echo "Compiling $circuit"
    nargo compile --force --package "$circuit"
done

# Regenerate constrained circuits (without unconstrained entrypoint)
./node_modules/.bin/tsx src/ts/scripts/circuit-builder.ts generate
