CWD := $(abspath $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST))))))

package_names := data_check_integrity \
				disclose_bytes \
				disclose_flags \
				exclusion_check_country \
				inclusion_check_country

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

