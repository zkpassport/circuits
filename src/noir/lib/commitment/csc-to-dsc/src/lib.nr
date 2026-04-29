use common::{
    calculate_certificate_root_v1, CertificateTreeLeaf,
    compute_certificate_tree_root_using_hash_path_v1, CSC_CERT_TYPE, hash_salt_country_tbs,
};
use utils::types::Alpha3CountryCode;

/*
# Sub-circuit A: CSC to DSC
# Verifies the CSCA signed the DSC, and the CSCA certificate is in the Certificate Registry
# under the published v1 certificate_registry_root.
#
#   state_root                = Poseidon2(certificate_tree_root, revocation_tree_root, masterlist_tree_root)
#   certificate_registry_root = Poseidon2(packed(schema_version[u16 BE] || timestamp[u32 BE]), state_root)
#
# The revocation and masterlist tree roots are bound to the published `certificate_registry_root`
# via the hash above, but their contents are not verified by this sub-circuit at the moment.
*/
pub fn commit_to_dsc<let CSC_KEY_SIZE: u32, let HASH_PATH_SIZE: u32, let TBS_CERT_SIZE: u32>(
    certificate_registry_root: Field,
    schema_version: u16,
    timestamp: u32,
    certificate_tree_index: Field,
    certificate_tree_hash_path: [Field; HASH_PATH_SIZE],
    certificate_tags: [Field; 3],
    country: Alpha3CountryCode,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    salt: Field,
    csc_pubkey: [u8; CSC_KEY_SIZE],
    csc_expiry: u32,
    csc_fingerprint: Field,
    revocation_tree_root: Field,
    masterlist_tree_root: Field,
) -> Field {
    // Verify the CSCA exists in the certificate tree and recover the cert tree root.
    let leaf = CertificateTreeLeaf {
        tags: certificate_tags,
        cert_type: CSC_CERT_TYPE,
        country,
        public_key: csc_pubkey,
        expiry: csc_expiry,
        fingerprint: csc_fingerprint,
    };
    let certificate_tree_root = compute_certificate_tree_root_using_hash_path_v1(
        leaf,
        certificate_tree_index,
        certificate_tree_hash_path,
    );
    // Reconstruct the published v1 certificate registry root and assert it matches the public input.
    let computed_root = calculate_certificate_root_v1(
        schema_version,
        timestamp,
        certificate_tree_root,
        revocation_tree_root,
        masterlist_tree_root,
    );
    assert(computed_root == certificate_registry_root, "Certificate registry root mismatch");
    // Output commitment glue
    let comm_out = hash_salt_country_tbs(salt, country, tbs_certificate);
    comm_out
}
