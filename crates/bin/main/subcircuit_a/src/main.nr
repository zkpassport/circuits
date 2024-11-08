/*
############################################################
# Circuit A
############################################################
# Verifies the CSC signed the DSC
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root (public)
certificate_registry_index
certificate_registry_hash_path
salt
registry_id (1 for ICAO PKD, 2 for Augmented)
cert_type (1 for CSC, 2 for DSC)
country (e.g. AUS, FRA)
csc_pubkey
dsc_pubkey
dsc_sig
dsc_tbs
dsc_tbs_pubkey_offset
comm_out                `H(salt, country, dsc_pubkey)`

# Checks
############################################################
- Check that leaf `H(registry_id, cert_type, country, csc_pubkey)` exists in tree with root certificate_registry_root
- Check that dsc_pubkey exists in dsc_tbs at offset dsc_tbs_pubkey_offset
- Check that dsc_sig is the signature of csc_pubkey over dsc_tbs
*/

use std::hash::pedersen_hash;

fn calculate_certificate_registry_leaf<let N: u32>(registry_id: Field, cert_type: Field, country: str<3>, csc_pubkey: [u8; N]) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N+5] = [0; N+5];
    result[0] = registry_id as Field;
    result[1] = cert_type as Field;
    result[2] = country_bytes[0] as Field;
    result[3] = country_bytes[1] as Field;
    result[4] = country_bytes[2] as Field;
    for i in 0..N {
        result[i+5] = csc_pubkey[i] as Field;
    }
    pedersen_hash(result)
}

fn hash_salt_country_pubkey<let N: u32>(salt: Field, country: str<3>, pubkey: [u8; N]) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N+4] = [0; N+4];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..N {
        result[i+4] = pubkey[i] as Field;
    }
    pedersen_hash(result)
}

#[recursive]
fn main(
    // Certificate registry merkle root
    certificate_registry_root: pub Field,
    // Index of CSC pub in the certificate registry
    certificate_registry_index: Field,
    // Hash path for CSC pubkey in the certificate registry
    // Depth 14 allows for up to 16,384 certificates
    certificate_registry_hash_path: [Field; 14],

    salt: Field,
    registry_id: Field,
    cert_type: Field,
    country: str<3>,
    csc_pubkey: [u8; 512],
    dsc_pubkey: [u8; 256],
    dsc_sig: [u8; 256],
    dsc_tbs: [u8; 1024],
    dsc_tbs_pubkey_offset: Field,

    comm_out: pub Field
) {
    // Verify csc_pubkey exists in certificate registry
    let leaf: Field = calculate_certificate_registry_leaf(registry_id, cert_type, country, csc_pubkey);
    let root = std::merkle::compute_merkle_root(leaf, certificate_registry_index, certificate_registry_hash_path);
    // assert(root == certificate_registry_root);

    // Output commitment glue
    assert(comm_out == hash_salt_country_pubkey(salt, country, dsc_pubkey));

    // println(f"leaf: {leaf}");
    // println(f"root: {root}");
    // println(f"comm_out: {comm_out}");
}

#[test]
fn test_main() {
    let certificate_registry_root: Field = 1;
    let certificate_registry_index: Field = 0;
    let certificate_registry_hash_path: [Field; 14] = [0; 14];
    let salt: Field = 42;
    let registry_id: Field = 1;
    let cert_type: Field = 1;
    let country: str<3> = "AUS";
    let csc_pubkey: [u8; 512] = [0; 512];
    let dsc_pubkey: [u8; 256] = [0; 256];
    let dsc_sig: [u8; 256] = [0; 256];
    let dsc_tbs: [u8; 1024] = [0; 1024];
    let dsc_tbs_pubkey_offset: Field = 123;

    let comm_out: Field = hash_salt_country_pubkey(salt, country, dsc_pubkey);

    main(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        salt,
        registry_id,
        cert_type,
        country,
        csc_pubkey,
        dsc_pubkey,
        dsc_sig,
        dsc_tbs,
        dsc_tbs_pubkey_offset,
        comm_out,
    );
}
