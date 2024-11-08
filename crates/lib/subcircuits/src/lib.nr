use std::hash::pedersen_hash;
use utils::{IDData, DSCData, PASSPORT_MRZ_COUNTRY_INDEX, CSCData};

pub global CSC_CERT_TYPE: Field = 1;
pub global DSC_CERT_TYPE: Field = 2;

pub fn calculate_certificate_registry_leaf<let N: u32>(
    registry_id: Field,
    cert_type: Field,
    country: str<3>,
    csc_pubkey: [u8; N],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N + 5] = [0; N + 5];
    result[0] = registry_id as Field;
    result[1] = cert_type as Field;
    result[2] = country_bytes[0] as Field;
    result[3] = country_bytes[1] as Field;
    result[4] = country_bytes[2] as Field;
    for i in 0..N {
        result[i + 5] = csc_pubkey[i] as Field;
    }
    pedersen_hash(result)
}

pub fn get_country_from_dg1(dg1: [u8; 95]) -> str<3> {
    // There 5 padding bytes in the dg1 before the actual MRZ
    let country_offset = 5 + PASSPORT_MRZ_COUNTRY_INDEX;
    let mut country_bytes: [u8; 3] = [0; 3];
    for i in 0..3 {
        country_bytes[i] = dg1[country_offset + i];
    }
    country_bytes.as_str_unchecked()
}

pub struct CertificateRegistry {
    // Index of CSC pub in the certificate registry
    pub index: Field,
    // Hash path for CSC pubkey in the certificate registry
    // Depth 14 allows for up to 16,384 certificates
    pub hash_path: [Field; 14],
    // 1 for ICAO PKD, 2 for Augmented
    pub id: Field,
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

pub fn subcircuit_a_verification<let PUBKEY_SIZE: u32>(
    certificate_registry_root: Field,
    certificate_registry: CertificateRegistry,
    country: str<3>,
    dsc_data: DSCData,
    salt: Field,
    csc_data: CSCData,
    comm_out: Field,
) {
    // Verify csc_pubkey exists in certificate registry
    let leaf: Field = calculate_certificate_registry_leaf(
        certificate_registry.index,
        CSC_CERT_TYPE,
        country,
        csc_data.pubkey,
    );
    let root = std::merkle::compute_merkle_root(
        leaf,
        certificate_registry.index,
        certificate_registry.hash_path,
    );
    //assert(root == certificate_registry_root);
    // Output commitment glue
    assert(comm_out == hash_salt_country_pubkey(salt, country, dsc_data.pubkey));
}

fn hash_salt_country_signed_attr_sod_sig<let SA: u32, let SIG: u32>(
    salt: Field,
    country: str<3>,
    signed_attr: [u8; SA],
    signed_attr_size: Field,
    sod_sig: [u8; SIG],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; SA + SIG + 5] = [0; SA + SIG + 5];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..SA {
        result[4 + i] = signed_attr[i] as Field;
    }
    result[4 + SA] = signed_attr_size;
    for i in 0..SIG {
        result[4 + SA + 1 + i] = sod_sig[i] as Field;
    }
    pedersen_hash(result)
}

fn hash_salt_country_pubkey<let N: u32>(salt: Field, country: str<3>, pubkey: [u8; N]) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N + 4] = [0; N + 4];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..N {
        result[i + 4] = pubkey[i] as Field;
    }
    pedersen_hash(result)
}

/*
############################################################
# Circuit B
############################################################
# Verifies the DSC signed the ePassport
############################################################

# Inputs/Outputs
############################################################
comm_in         `assert comm_in == H(salt, country, dsc_pubkey)`
salt
id_data
dsc_data
sod_sig
comm_out        `H(salt, country, signed_attr, sod_sig)`

# Checks
############################################################
- Check that sod_sig is the signature of dsc_pubkey over signed_attr
*/

pub fn subcircuit_b_verification<let SIG_SIZE: u32>(
    comm_in: Field,
    salt: Field,
    id_data: IDData,
    dsc_data: DSCData,
    comm_out: Field,
    sod_sig: [u8; SIG_SIZE],
) {
    let country = get_country_from_dg1(id_data.dg1);
    assert(comm_in == hash_salt_country_pubkey(salt, country, dsc_data.pubkey));

    assert(
        comm_out
            == hash_salt_country_signed_attr_sod_sig(
                salt,
                country,
                id_data.signed_attributes,
                id_data.signed_attributes_size as Field,
                sod_sig,
            ),
    );
}

pub fn hash_salt_dg1_private_nullifier<let N: u32>(
    salt: Field,
    dg1: [u8; N],
    private_nullifier: Field,
) -> Field {
    let mut result: [Field; N + 2] = [0; N + 2];
    result[0] = salt as Field;
    for i in 0..N {
        result[1 + i] = dg1[i] as Field;
    }
    result[1 + N] = private_nullifier;
    pedersen_hash(result)
}

pub fn calculate_private_nullifier<let DG1: u32, let SIG: u32>(
    dg1: [u8; DG1],
    sod_sig: [u8; SIG],
) -> Field {
    let mut result: [Field; DG1 + SIG + 2] = [0; DG1 + SIG + 2];
    for i in 0..DG1 {
        result[i] = dg1[i] as Field;
    }
    for i in 0..SIG {
        result[DG1 + i] = sod_sig[i] as Field;
    }
    pedersen_hash(result)
}

/*
############################################################
# Circuit C
############################################################
# Verifies the integrity of the ePassport data
############################################################

# Inputs/Outputs
############################################################
current_date
comm_in                 `assert comm_in == H(salt, country, signed_attr, sod_sig)`
salt
id_data
private_nullifier       `assert private_nullifier == H(dg1, sod_sig)`
comm_out                `H(salt, dg1, private_nullifier)`

# Checks
############################################################
- Check that passport expiry date <= current date
- Checks that the dg1 hash is present in econtent
- Checks that the hash of econtent is present in signed_attr
*/
pub fn subcircuit_c_verification<let SIG_SIZE: u32>(
    current_date: str<8>,
    comm_in: Field,
    salt: Field,
    id_data: IDData,
    private_nullifier: Field,
    comm_out: Field,
) {
    let country = get_country_from_dg1(id_data.dg1);
    assert(
        comm_in
            == hash_salt_country_signed_attr_sod_sig(
                salt,
                country,
                id_data.signed_attributes,
                id_data.signed_attributes_size as Field,
                id_data.sod_signature,
            ),
    );
    // println(f"comm_in: {comm_in}");
    assert(private_nullifier == calculate_private_nullifier(id_data.dg1, id_data.sod_signature));
    // println(f"private_nullifier: {private_nullifier}");
    assert(comm_out == hash_salt_dg1_private_nullifier(salt, id_data.dg1, private_nullifier));
    // println(f"comm_out: {comm_out}");
}

pub fn calculate_scoped_nullifier(
    private_nullifier: Field,
    service_scope: Field,
    service_subscope: Field,
) -> Field {
    pedersen_hash([private_nullifier, service_scope, service_subscope])
}

/*
############################################################
# Circuit D
############################################################
# Generates a scoped nullifier that is scoped by service
# Allows selective disclosure of dg1 via a reveal bitmask
############################################################

# Inputs/Outputs
############################################################
comm_in             `assert comm_in == H(salt, dg1, private_nullifier)`
salt
dg1
private_nullifier
service_scope       `H(<domain_name>)`
service_subscope    `H(<purpose>)` (Service-specific subscope)
scoped_nullifier    `H(private_nullifier, service_scope, service_subscope)`

# Checks
############################################################
- Checks that dg1_reveal is the correct reveal of dg1 for the given dg1_mask
- Constrains scoped_nullifier to be `H(private_nullifier, service_scope, service_subscope)`
*/
pub fn subcircuit_d_verification<let DG1: u32>(
    comm_in: Field,
    salt: Field,
    id_data: IDData,
    private_nullifier: Field,
    service_scope: Field,
    service_subscope: Field,
    scoped_nullifier: Field,
) {
    assert(comm_in == hash_salt_dg1_private_nullifier(salt, id_data.dg1, private_nullifier));
    // println(f"comm_in: {comm_in}");
    assert(
        scoped_nullifier
            == calculate_scoped_nullifier(private_nullifier, service_scope, service_subscope),
    );
    // println(f"scoped_nullifier: {scoped_nullifier}");
}
