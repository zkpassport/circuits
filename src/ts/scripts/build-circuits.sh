#!/bin/bash

set -e

# Use NARGO_PATH if set, otherwise fall back to 'nargo'
NARGO=${NARGO_PATH:-nargo}

$NARGO compile --force --package sig_check_dsc_tbs_1500_rsa_pkcs_4096
$NARGO compile --force --package sig_check_id_data_tbs_1500_rsa_pkcs_2048
$NARGO compile --force --package data_check_integrity
$NARGO compile --force --package disclose_bytes
