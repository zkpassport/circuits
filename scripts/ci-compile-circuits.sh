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
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_1500_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_1500_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256"
    "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512"
    "sig_check_id_data_tbs_700_ecdsa_nist_p384_sha384"
    "data_check_integrity_sha256"
    "data_check_integrity_sha384"
    "data_check_integrity_sha512"
    "disclose_flags"
    "disclose_bytes"
    "inclusion_check_nationality"
    "exclusion_check_nationality"
    "inclusion_check_issuing_country"
    "exclusion_check_issuing_country"
    "compare_age"
    "compare_expiry"
    "compare_birthdate"
)

for circuit in "${CIRCUITS[@]}"; do
    $NARGO_BIN compile --force --package "$circuit"
done
