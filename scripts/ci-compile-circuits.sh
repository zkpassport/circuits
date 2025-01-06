#!/bin/bash

# This script compiles a subset of Noir circuits required for CI pipeline.

set -e
BIN=${NARGO_PATH:-nargo}

# Update the circuits to be unconstrained, so that we can test the logic
# of the circuit for given inputs without doing fully constrained proving.
bun run src/ts/scripts/circuit-builder.ts unconstrained

$BIN compile --force --package sig_check_dsc_tbs_1500_rsa_pkcs_4096
$BIN compile --force --package sig_check_id_data_tbs_1500_rsa_pkcs_2048
$BIN compile --force --package data_check_integrity
$BIN compile --force --package disclose_flags
