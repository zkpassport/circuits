#!/bin/bash

set -e

nargo compile --package sig_check_dsc_rsa_pkcs_4096
nargo compile --package sig_check_id_data_rsa_pkcs_2048
nargo compile --package data_check_integrity
nargo compile --package disclose_bytes
nargo compile --package outer
