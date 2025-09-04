use poseidon::poseidon2::Poseidon2;
use utils::{get_issuing_country_from_mrz, get_nationality_from_mrz};

// Missing tests.
// Visually inspected.
// We should technically static_assert that the list size N is less than 2^31,
// since otherwise the conversion from the i32 result of this function back to a u32 (`as u32`)
// in other functions will yield a positive number. This would enable an attacker to access 
// elements 2^31..2^32 of a list (e.g. in your `check_nationality_inclusion` function). 
// But of course, with the way this function is actually called, the list size is actually size 200, 
// and the plonk trusted setup is much smaller than 2^31 points, so we're probably already safe.
// (I just get nervous when I see signed integers).
unconstrained fn get_index<let N: u32>(list: [str<3>; N], value: [u8; 3]) -> i32 {
    let mut index: i32 = -1;
    for i in 0..N {
        let list_item = list[i].as_bytes();
        if (list_item[0] == value[0]) & (list_item[1] == value[1]) & (list_item[2] == value[2]) {
            index = i as i32;
        }
    }
    index
}

// Missing tests.
// Visually inspected.
// TODO: ensure the country_list can't be padded (near the end) with malicious / duplicate country codes.
/// Check if the nationality from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_nationality_inclusion<let N: u32>(dg1: [u8; 95], country_list: [str<3>; N]) {
    let nationality_bytes = get_nationality_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { get_index(country_list, nationality_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the nationality is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index as u32].as_bytes();

    // You could instead compare equality of the entire length-3 arrays in a single assertion, 
    // since arrays implement the Eq trait.
    assert_eq(nationality_bytes[0], country_code[0], "Nationality does not match the country code");
    assert_eq(nationality_bytes[1], country_code[1], "Nationality does not match the country code");
    assert_eq(nationality_bytes[2], country_code[2], "Nationality does not match the country code");
}

// Missing tests.
// Visually inspected.
/// Check if the issuing country from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_issuing_country_inclusion<let N: u32>(dg1: [u8; 95], country_list: [str<3>; N]) {
    let issuing_country_bytes = get_issuing_country_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { get_index(country_list, issuing_country_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the issuing country is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index as u32].as_bytes();

    // You could instead compare equality of the entire length-3 arrays in a single assertion, 
    // since arrays implement the Eq trait.
    assert_eq(
        issuing_country_bytes[0],
        country_code[0],
        "Issuing country does not match the country code",
    );
    assert_eq(
        issuing_country_bytes[1],
        country_code[1],
        "Issuing country does not match the country code",
    );
    assert_eq(
        issuing_country_bytes[2],
        country_code[2],
        "Issuing country does not match the country code",
    );
}

// Visually inspected.
// Missing tests.
// TODO: check that the verifier actually checks the preimage of this param commitment (or has already precomputed this param commitment). We don't want someone sneaking a country code in the final entries of the list.
// Visually inspected.
// Inefficient packing. This uses N + 1 fields instead of roughly ceil((3*N + 1) / 31) fields,
// so is technically doing unnecessary poseidon2 constraints. Roughly ~13k unnecessary constraints.
// You could instead flatten entire country list into one bytes array, and then convert those
// bytes into fields, using a function in the utils.nr file.
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
pub fn calculate_param_commitment<let N: u32>(proof_type: u8, country_list: [str<3>; N]) -> Field {
    let mut params = [0 as Field; N + 1];
    params[0] = proof_type as Field;
    for i in 1..N + 1 {
        let country_code = country_list[i - 1].as_bytes();
        let country_sum: u32 = country_code[0] as u32 * 0x10000
            + country_code[1] as u32 * 0x100
            + country_code[2] as u32;
        params[i] = country_sum as Field;
    }
    Poseidon2::hash(params, N + 1)
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
    country_list: [str<3>; N],
) -> Field {
    let mut params = [0 as u8; N * 3 + 1];
    params[0] = proof_type;
    for i in 0..N {
        let country_code = country_list[i].as_bytes();
        params[i * 3 + 1] = country_code[0];
        params[i * 3 + 2] = country_code[1];
        params[i * 3 + 3] = country_code[2];
    }
    let hash = sha256::sha256_var(params, (N * 3 + 1) as u64);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
