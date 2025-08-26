#!/bin/bash

# This script compiles a subset of circuits used in CI tests

set -euo pipefail

# Circuits to compile
CIRCUITS=(
    "sig_check_dsc_tbs_1000_rsa_pkcs_6144_sha256"
    "sig_check_id_data_tbs_1000_rsa_pkcs_4096_sha1"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha1"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha1"
    "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha1"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_192r1_sha1"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_224r1_sha1"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256"
    "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512"
    "sig_check_id_data_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_512r1_sha512"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_192r1_sha1"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_224r1_sha1"
    "data_check_integrity_sa_sha1_dg_sha1"
    "data_check_integrity_sa_sha256_dg_sha256"
    "data_check_integrity_sa_sha384_dg_sha384"
    "data_check_integrity_sa_sha512_dg_sha512"
    "data_check_integrity_sa_sha224_dg_sha224"
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
    "exclusion_check_sanctions"
    "exclusion_check_sanctions_evm"
    "compare_age"
    "compare_age_evm"
    "compare_expiry"
    "compare_expiry_evm"
    "compare_birthdate"
    "compare_birthdate_evm"
    "bind"
    "bind_evm"
)

# Ensure circuits are generated
./node_modules/.bin/tsx src/ts/scripts/circuit-builder.ts generate && nargo fmt

# Compile circuits into unconstrained brillig
for circuit in "${CIRCUITS[@]}"; do
    echo "Compiling $circuit"
    nargo compile --force --force-brillig --package "$circuit"
    echo "Compiled $circuit"
done
