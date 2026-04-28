use common::{calculate_certificate_root_using_hash_path_v0, CSC_CERT_TYPE, hash_salt_country_tbs};
use utils::types::Alpha3CountryCode;

/*
# Sub-circuit A: CSC to DSC
# Verifies the CSCA signed the DSC, and the CSCA certificate is in the Certificate Registry
*/

pub fn commit_to_dsc<let CSC_KEY_SIZE: u32, let HASH_PATH_SIZE: u32, let TBS_CERT_SIZE: u32>(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; HASH_PATH_SIZE],
    certificate_tags: [Field; 3],
    country: Alpha3CountryCode,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    salt: Field,
    csc_pubkey: [u8; CSC_KEY_SIZE],
) -> Field {
    // Verify csc_pubkey exists in certificate registry
    let root = calculate_certificate_root_using_hash_path_v0(
        certificate_tags,
        CSC_CERT_TYPE,
        country,
        csc_pubkey,
        certificate_registry_index,
        certificate_registry_hash_path,
    );
    assert(root == certificate_registry_root, "Certificate registry root mismatch");
    // Output commitment glue
    let comm_out = hash_salt_country_tbs(salt, country, tbs_certificate);
    comm_out
}
