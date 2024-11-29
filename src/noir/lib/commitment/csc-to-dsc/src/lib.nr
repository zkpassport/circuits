use common::{calculate_certificate_registry_leaf, hash_salt_country_dsc_tbs, CSC_CERT_TYPE};
use merkle_tree::merkle::MerkleTree;
use std::hash::poseidon2::Poseidon2;

fn hasher<let N: u32>(leaves: [Field; N]) -> Field {
    Poseidon2::hash(leaves, N)
}

/*
############################################################
# Circuit A
############################################################
# Verifies the CSC signed the DSC
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root (public)
certificate_registry
salt
country
csc_pubkey
dsc_pubkey
dsc_data
comm_out                `H(salt, country, dsc_pubkey)`

# Checks
############################################################
- Check that leaf `H(registry_id, cert_type, country, csc_pubkey)` exists in tree with root certificate_registry_root
- Check that dsc_pubkey exists in dsc_tbs at offset dsc_tbs_pubkey_offset
- Check that dsc_sig is the signature of csc_pubkey over dsc_tbs
*/

pub fn commit_to_dsc<let CSC_KEY_SIZE: u32, let HASH_PATH_SIZE: u32>(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; HASH_PATH_SIZE],
    certificate_registry_id: Field,
    country: str<3>,
    tbs_certificate: [u8; 1500],
    salt: Field,
    csc_pubkey: [u8; CSC_KEY_SIZE],
) -> Field {
    // Verify csc_pubkey exists in certificate registry
    let leaf: Field = calculate_certificate_registry_leaf(
        certificate_registry_id,
        CSC_CERT_TYPE,
        country,
        csc_pubkey,
    );
    let mut mt = MerkleTree::new(hasher);
    let root = mt.calculate_root(leaf, certificate_registry_index, certificate_registry_hash_path);
    assert(root == certificate_registry_root);
    // Output commitment glue
    let comm_out = hash_salt_country_dsc_tbs(salt, country, tbs_certificate);
    comm_out
}
