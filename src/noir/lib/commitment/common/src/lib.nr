//use std::hash::pedersen_hash;
use std::hash::poseidon2::Poseidon2;
use utils::PASSPORT_MRZ_COUNTRY_INDEX;

pub global CSC_CERT_TYPE: Field = 1;
pub global DSC_CERT_TYPE: Field = 2;

pub fn calculate_scoped_nullifier(
    private_nullifier: Field,
    service_scope: Field,
    service_subscope: Field,
) -> Field {
    Poseidon2::hash([private_nullifier, service_scope, service_subscope], 3)
}

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
    Poseidon2::hash(result, N + 5)
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

pub fn hash_salt_country_tbs<let TBS_MAX_SIZE: u32>(
    salt: Field,
    country: str<3>,
    tbs: [u8; TBS_MAX_SIZE],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; TBS_MAX_SIZE + 4] = [0; TBS_MAX_SIZE + 4];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..TBS_MAX_SIZE {
        result[4 + i] = tbs[i] as Field;
    }
    Poseidon2::hash(result, TBS_MAX_SIZE + 4)
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
    Poseidon2::hash(result, N + 2)
}

pub fn calculate_private_nullifier<let DG1: u32, let SIG: u32>(
    dg1: [u8; DG1],
    sod_sig: [u8; SIG],
) -> Field {
    let mut result: [Field; DG1 + SIG] = [0; DG1 + SIG];
    for i in 0..DG1 {
        result[i] = dg1[i] as Field;
    }
    for i in 0..SIG {
        result[DG1 + i] = sod_sig[i] as Field;
    }
    Poseidon2::hash(result, DG1 + SIG)
}

pub fn hash_salt_country_signed_attr_dg1_private_nullifier<let SA: u32>(
    salt: Field,
    country: str<3>,
    signed_attr: [u8; SA],
    signed_attr_size: Field,
    dg1: [u8; 95],
    private_nullifier: Field,
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; SA + 101] = [0; SA + 101];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..SA {
        result[4 + i] = signed_attr[i] as Field;
    }
    result[4 + SA] = signed_attr_size;
    for i in 0..95 {
        result[4 + SA + 1 + i] = dg1[i] as Field;
    }
    result[4 + SA + 1 + 95] = private_nullifier;
    Poseidon2::hash(result, SA + 101)
}
