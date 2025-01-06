#!/bin/bash

# This script compiles a subset of Noir circuits required for CI pipeline.

set -euo pipefail

: ${NARGO_BIN:=nargo}
: ${BUN_BIN:=bun}

# Update the circuits to be unconstrained, so that we can test the logic
# of the circuit for given inputs without doing fully constrained proving.
$BUN_BIN run src/ts/scripts/circuit-builder.ts unconstrained

# Circuits to compile
CIRCUITS=(
    "sig_check_dsc_tbs_1500_rsa_pkcs_4096"
    "sig_check_id_data_tbs_1500_rsa_pkcs_2048"
    "data_check_integrity"
    "disclose_flags"
)

for circuit in "${CIRCUITS[@]}"; do
    $NARGO_BIN compile --force --package "$circuit"
done
