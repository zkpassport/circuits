use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::EMPTY_ALPHA3_COUNTRY_CODE,
    get_issuing_country_from_mrz,
    get_nationality_from_mrz,
    types::{Alpha3CountryCode, DG1Data},
};

pub mod tests;

pub unconstrained fn unsafe_get_index<let N: u32>(
    list: [Alpha3CountryCode; N],
    value: [u8; 3],
) -> i32 {
    // In practice, the list will be 200 countries, so this check might be overdoing it
    std::static_assert(N < 0x80000000, "Country list size must be less than 2^31");

    let mut index: i32 = -1;
    // If the value is the empty country code, then we skip the check
    // and let the function return -1 as if it was not found
    if value != EMPTY_ALPHA3_COUNTRY_CODE.as_bytes() {
        for i in 0..N {
            let list_item = list[i].as_bytes();
            if (list_item == value) {
                index = i as i32;
            }
        }
    }
    index
}

/// Check if the nationality from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_nationality_inclusion<let N: u32>(dg1: DG1Data, country_list: [Alpha3CountryCode; N]) {
    let nationality_bytes = get_nationality_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { unsafe_get_index(country_list, nationality_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the nationality is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index as u32].as_bytes();
    assert_eq(nationality_bytes, country_code, "Nationality does not match the country code");
}

/// Check if the issuing country from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_issuing_country_inclusion<let N: u32>(
    dg1: DG1Data,
    country_list: [Alpha3CountryCode; N],
) {
    let issuing_country_bytes = get_issuing_country_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { unsafe_get_index(country_list, issuing_country_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the issuing country is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index as u32].as_bytes();
    assert_eq(
        issuing_country_bytes,
        country_code,
        "Issuing country does not match the country code",
    );
}

/// Calculate the commitment of the country list using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `country_list`: The list of countries
///
/// # Returns
///
/// * `commitment`: The commitment of the country list
pub fn calculate_param_commitment<let N: u32>(
    proof_type: u8,
    country_list: [Alpha3CountryCode; N],
) -> Field {
    let mut params = [0 as Field; N + 2];
    params[0] = proof_type as Field;
    params[1] = (params.len() - 2) as Field;
    for i in 2..N + 2 {
        let country_code = country_list[i - 2].as_bytes();
        let country_sum: u32 = country_code[0] as u32 * 0x10000
            + country_code[1] as u32 * 0x100
            + country_code[2] as u32;
        params[i] = country_sum as Field;
    }
    Poseidon2::hash(params, params.len())
}

/// Calculate the commitment of the country list using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `country_list`: The list of countries
///
/// # Returns
///
/// * `commitment`: The commitment of the country list
pub fn calculate_param_commitment_sha2<let N: u32>(
    proof_type: u8,
    country_list: [Alpha3CountryCode; N],
) -> Field {
    let mut params = [0 as u8; N * 3 + 3];
    params[0] = proof_type;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    let mut base_offset = 3;
    for i in 0..N {
        let country_code = country_list[i].as_bytes();
        params[base_offset + i * 3] = country_code[0];
        params[base_offset + i * 3 + 1] = country_code[1];
        params[base_offset + i * 3 + 2] = country_code[2];
    }
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
