#!/bin/bash

set -e

nargo compile --force --package sig_check_dsc_tbs_1500_rsa_pkcs_4096
nargo compile --force --package sig_check_id_data_tbs_1500_rsa_pkcs_2048
nargo compile --force --package data_check_integrity
nargo compile --force --package disclose_bytes
