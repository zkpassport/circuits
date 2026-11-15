#!/bin/bash

# This script compiles a subset of circuits used in CI tests

set -euo pipefail

# Number of circuits to compile in parallel. Override with e.g.
# `JOBS=16 scripts/ci-compile-circuits.sh`.
JOBS="${JOBS:-$(( $(nproc) < 8 ? $(nproc) : 8 ))}"

# Circuits to compile
CIRCUITS=(
    "sig_check_dsc_tbs_1000_rsa_pkcs_6144_sha256"
    "sig_check_id_data_tbs_1000_rsa_pkcs_4096_sha1"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha512"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha256"
    "sig_check_dsc_tbs_700_ecdsa_nist_p384_sha1"
    "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha384"
    "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha1"
    "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha1"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_192r1_sha1"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_224r1_sha1"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_256r1_sha256"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_384r1_sha384"
    "sig_check_dsc_tbs_700_ecdsa_brainpool_512r1_sha512"
    "sig_check_dsc_tbs_700_ecdsa_nist_p256_sha256"
    "sig_check_id_data_tbs_700_ecdsa_nist_p192_sha1"
    "sig_check_id_data_tbs_700_ecdsa_nist_p224_sha224"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha1"
    "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"
    "sig_check_id_data_tbs_700_ecdsa_nist_p256_sha256"
    "sig_check_dsc_tbs_700_ecdsa_nist_p521_sha512"
    "sig_check_id_data_tbs_700_ecdsa_nist_p384_sha384"
    "sig_check_id_data_tbs_700_ecdsa_nist_p521_sha512"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_256r1_sha256"
    "sig_check_id_data_tbs_700_ecdsa_brainpool_384r1_sha384"
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

# Facematch circuits are compiled constrained (force brillig fails for these at
# present). 
# TODO: Fix this once the force brillig issue is resolved.

FACEMATCH=(
    "facematch_ios"
    "facematch_ios_evm"
    "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256"
    "facematch_android_rk_rsa_ik_count_3_ik_ecdsa_p384_sha384_ik_ecdsa_p256_sha256_ik_ecdsa_p256_sha256_evm"
)

echo "Compiling ${#CIRCUITS[@]} brillig + ${#FACEMATCH[@]} facematch circuits with $JOBS parallel jobs"

printf '%s\n' "${CIRCUITS[@]}" | xargs -P "$JOBS" -n1 nargo compile --force --force-brillig --package
printf '%s\n' "${FACEMATCH[@]}" | xargs -P "$JOBS" -n1 nargo compile --force --package

echo "All circuits compiled -> target/*.json ($(ls target/*.json 2>/dev/null | wc -l) artifacts)"
