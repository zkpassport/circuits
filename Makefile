CWD := $(abspath $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

package_names := data_check_integrity \
				disclose_bytes \
				sig_check_dsc_ecdsa_nist_p256 \
				sig_check_dsc_ecdsa_nist_p384 \
				sig_check_dsc_ecdsa_nist_p521 \
				sig_check_dsc_ecdsa_brainpool_256r1 \
				sig_check_dsc_ecdsa_brainpool_256t1 \
				sig_check_dsc_ecdsa_brainpool_384r1 \
				sig_check_dsc_ecdsa_brainpool_384t1 \
				sig_check_dsc_ecdsa_brainpool_512r1 \
				sig_check_dsc_ecdsa_brainpool_512t1 \
				sig_check_dsc_rsa_pkcs_1024 \
				sig_check_dsc_rsa_pkcs_2048 \
				sig_check_dsc_rsa_pkcs_3072 \
				sig_check_dsc_rsa_pkcs_4096 \
				sig_check_dsc_rsa_pss_1024 \
				sig_check_dsc_rsa_pss_2048 \
				sig_check_dsc_rsa_pss_3072 \
				sig_check_dsc_rsa_pss_4096 \
				sig_check_id_data_ecdsa_nist_p256 \
				sig_check_id_data_ecdsa_nist_p384 \
				sig_check_id_data_ecdsa_nist_p521 \
				sig_check_id_data_ecdsa_brainpool_256r1 \
				sig_check_id_data_ecdsa_brainpool_256t1 \
				sig_check_id_data_ecdsa_brainpool_384r1 \
				sig_check_id_data_ecdsa_brainpool_384t1 \
				sig_check_id_data_ecdsa_brainpool_512r1 \
				sig_check_id_data_ecdsa_brainpool_512t1 \
				sig_check_id_data_rsa_pkcs_1024 \
				sig_check_id_data_rsa_pkcs_2048 \
				sig_check_id_data_rsa_pkcs_3072 \
				sig_check_id_data_rsa_pkcs_4096 \
				sig_check_id_data_rsa_pss_1024 \
				sig_check_id_data_rsa_pss_2048 \
				sig_check_id_data_rsa_pss_3072 \
				sig_check_id_data_rsa_pss_4096

compileAll:
	for pkg in $(package_names); do \
		echo "Compiling $$pkg"; \
		$(CWD)/scripts/info.sh $$pkg; \
	done

proveAll:
	for pkg in $(package_names); do \
		echo "Proving $$pkg"; \
		$(CWD)/scripts/prove-honk.sh $$pkg; \
	done

