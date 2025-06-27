#!/bin/bash

# This script compiles a subset of Noir circuits required for CI pipeline.

set -euo pipefail

# Generate unconstrained circuits, so that we can test the circuit logic
# for given inputs without doing fully constrained proving
./node_modules/.bin/tsx src/ts/scripts/circuit-builder.ts generate unconstrained

# Circuits to compile for integration tests
CIRCUITS=(
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_1500_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha1"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha1"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_1500_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256"
    "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512"
    "sig_check_id_data_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_512r1_sha512"
    "data_check_integrity_sa_sha1_dg_sha1"
    "data_check_integrity_sa_sha256_dg_sha256"
    "data_check_integrity_sa_sha384_dg_sha384"
    "data_check_integrity_sa_sha512_dg_sha512"
    "disclose_flags"
    "disclose_bytes"
    "disclose_bytes_evm"
    "inclusion_check_nationality"
    "inclusion_check_nationality_evm"
    "exclusion_check_nationality"
    "exclusion_check_nationality_evm"
    "inclusion_check_issuing_country"
    "inclusion_check_issuing_country_evm"
    "exclusion_check_issuing_country"
    "exclusion_check_issuing_country_evm"
    "inclusion_check_sanctions"
    "inclusion_check_sanctions_evm"
    "compare_age"
    "compare_age_evm"
    "compare_expiry"
    "compare_expiry_evm"
    "compare_birthdate"
    "compare_birthdate_evm"
    "bind"
    "bind_evm"
)

for circuit in "${CIRCUITS[@]}"; do
    nargo compile --force --package "$circuit"
done

# Regenerate constrained circuits (without unconstrained entrypoint)
./node_modules/.bin/tsx src/ts/scripts/circuit-builder.ts generate
