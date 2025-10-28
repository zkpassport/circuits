use poseidon::poseidon2::Poseidon2;
use utils::{get_issuing_country_from_mrz, get_nationality_from_mrz, types::DG1Data};

pub mod tests;

pub unconstrained fn unsafe_get_closest_index<let N: u32>(
    sorted_list: [u32; N],
    value: u32,
) -> i64 {
    let mut index: i64 = -1;
    for i in 0..N {
        if sorted_list[i] > value {
            index = i as i64;
            break;
        }
    }
    index
}

pub unconstrained fn unsafe_get_last_index<let N: u32>(sorted_list: [u32; N]) -> i64 {
    let mut index: i64 = -1;
    // If the last element is not 0, then it should be the last index
    // Other conditions will be checked in constrained code
    if sorted_list[N - 1] != 0 {
        index = (N - 1) as i64;
    }

    if sorted_list[0] != 0 {
        for i in 0..N {
            if sorted_list[i] == 0 {
                index = (i - 1) as i64;
                break;
            }
        }
    }
    index
}

pub fn constrain_last_index<let N: u32>(sorted_list: [u32; N], last_index: i64) {
    if last_index != (N - 1) as i64 {
        // i.e. if it's not the last index in the array.
        // This will fail for last_index >= N - 1, due to out of bounds errors.

        // If there are still 0s after the last nonzero element,
        // then we need to check that the next element is 0
        assert_eq(
            sorted_list[(last_index + 1) as u32],
            0,
            "The list is not padded with 0s after the last nonzero element",
        );
    }

    if last_index != -1 {
        // I.e. if it's not the first index in the array.
        // This will fail if last_index <= -2 also, due to out of bounds errors.
        assert(sorted_list[last_index as u32] != 0, "The item at the last index must be nonzero");
    }
}

pub fn get_last_index<let N: u32>(sorted_list: [u32; N]) -> i64 {
    // Safety: the returned value is constrained below (with the assumptions that:
    // - the list is sorted
    // - every item after the first 0 is also 0
    // )
    let last_index = unsafe { unsafe_get_last_index(sorted_list) };

    constrain_last_index(sorted_list, last_index);

    last_index
}

pub fn constrain_closest_index<let N: u32>(
    sorted_list: [u32; N],
    value: u32,
    closest_index_from_above: i64,
) {
    assert(closest_index_from_above < 0x80000000, "Closest index out of range"); // < 2^31

    // Examples:
    //    [FRA , USA , GBR , JPN , IRL , PRT , ITA]
    //  ^   ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^   ^
    //  |   |  |  |  |  |  |  |  |  |  |  |  |  |   |
    //  0   1  1  2  2  3  3  4  4  5  5  6  6 -1  -1 <-- the returned closest index (from above), if the
    //                                                    `value` sits at or between these
    //                                                     elements in the array.
    //
    //    [FRA , USA , GBR , JPN ,  0  ,  0  ,  0]
    //  ^   ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^  ^   ^
    //  |   |  |  |  |  |  |  |  |  |  |  |  |  |   |
    //  0   1  1  2  2  3  3 -1 -1 -1 -1 -1 -1 -1  -1 <-- the returned closest index (from above), if the
    //                                             `value` sits at or between these
    //                                              elements in the array.
    // Note: The country codes are converted to u32s by summing (weighted)
    // the ASCII codes of the letters so the list is sorted in ascending order
    // of the country codes.

    // If the index is 0, it implies the whole list is > value, since it's sorted
    if closest_index_from_above == 0 {
        // So if the value is less than the first item, then it is not in the list
        assert(value < sorted_list[0], "The country is in the list (not less than the first item)");
    }
    // Else, if the index is -1, then the `value` might still be at the "last" nonzero position in the list
    else if closest_index_from_above == -1 {
        // Get the index of the last item of the sorted list,
        // i.e. the index of the last nonzero element in the list
        let last_index = get_last_index(sorted_list);
        // We ensure that the `value` is greater than the last item,
        // which implies the value is not in the list (since it's sorted)
        assert(
            sorted_list[last_index as u32] < value,
            "The country is in the list (not greater than the last item)",
        );
    } else {
        let index = closest_index_from_above as u32;
        // The `value` is somewhere in the middle of the first and last element of the list.
        // We don't want the `value` to equal any item in the list, so we sandwich it between
        // two consecutive items in the list:
        // the one supposed to be less than the value and the one supposed to be greater than the value
        // Note: Will fail with out of bounds errors if index >= N.
        assert(
            sorted_list[index - 1] < value,
            "The country is in the list (not greater than the expected lower bound)",
        );
        assert(
            value < sorted_list[index],
            "The country is in the list (not less than the expected upper bound)",
        );
    }
}

pub fn check_country_list_sorted<let N: u32>(country_list: [u32; N]) -> bool {
    let mut result = true;
    let mut foundAZero = false;
    assert(country_list[0] != 0, "Country list cannot start with 0");
    for i in 0..N - 1 {
        // Zeroes mark the end of the list (i.e. start of the padding)
        if country_list[i + 1] == 0 {
            foundAZero = true;
        }
        // If the current element is greater than the next element, then the list is not sorted
        // We also want to make sure there are no duplicates so we actually check greater than or equal
        if !foundAZero & (country_list[i] >= country_list[i + 1]) {
            result = false;
        }
        if (foundAZero) {
            assert(
                country_list[i + 1] == 0,
                "Country list cannot contain 0s before the last non-0 element",
            );
        }
    }
    result
}

fn check_exclusion<let N: u32>(country_sum: u32, country_list: [u32; N]) {
    // Safety: since the list is assumed to be sorted in ascending order, we can get the index to check against
    // from an unconstrained function
    let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, country_sum) };

    constrain_closest_index(country_list, country_sum, closest_index_from_above);
}

/// Check if the nationality from the MRZ is not in the country list
/// The list of countries is assumed to be sorted in ascending order
/// So it must come either from a public input that can be independently checked
/// or from a previous in-circuit check that the list is sorted
/// If the list is not sorted, the proof will fail to generate
///
/// # Arguments
///
/// * `dg1` - The DG1 of the passport or ID card
/// * `country_list` - The sorted list of countries to check against, must be formatted as a list of u32
/// which are the Alpha-3 codes of the countries with each letter ASCII code put together using a weighted sum.
/// e.g. for "FRA", the sum is 70 * 2^16 (0x10000) + 82 * 2^8 (0x100) + 65 = 4587520 + 20992 + 65 = 4608577
pub fn check_nationality_exclusion<let N: u32>(dg1: DG1Data, country_list: [u32; N]) {
    // Check that the list is sorted in ascending order
    assert(
        check_country_list_sorted(country_list),
        "Country list is not sorted in ascending order",
    );

    let nationality_bytes = get_nationality_from_mrz(dg1);
    let nationality_sum: u32 = nationality_bytes[0] as u32 * 0x10000
        + nationality_bytes[1] as u32 * 0x100
        + nationality_bytes[2] as u32;

    check_exclusion(nationality_sum, country_list);
}

/// Check if the issuing country from the MRZ is not in the country list
/// The list of countries is assumed to be sorted in ascending order
/// So it must come either from a public input that can be independently checked
/// or from a previous in-circuit check that the list is sorted
/// If the list is not sorted, the proof will fail to generate
pub fn check_issuing_country_exclusion<let N: u32>(dg1: DG1Data, country_list: [u32; N]) {
    // Check that the list is sorted in ascending order
    assert(
        check_country_list_sorted(country_list),
        "Country list is not sorted in ascending order",
    );

    let issuing_country_bytes = get_issuing_country_from_mrz(dg1);
    let issuing_country_sum: u32 = issuing_country_bytes[0] as u32 * 0x10000
        + issuing_country_bytes[1] as u32 * 0x100
        + issuing_country_bytes[2] as u32;

    check_exclusion(issuing_country_sum, country_list);
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
pub fn calculate_param_commitment<let N: u32>(proof_type: u8, country_list: [u32; N]) -> Field {
    let mut params = [0 as Field; N + 2];
    params[0] = proof_type as Field;
    params[1] = (params.len() - 2) as Field;
    for i in 2..N + 2 {
        params[i] = country_list[i - 2] as Field;
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
    country_list: [u32; N],
) -> Field {
    let mut params = [0 as u8; N * 3 + 3];
    params[0] = proof_type;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    let base_offset = 3;
    for i in 0..N {
        params[base_offset + i * 3] = (country_list[i] >> 16) as u8;
        params[base_offset + i * 3 + 1] = ((country_list[i] >> 8) & 0xFF) as u8;
        params[base_offset + i * 3 + 2] = (country_list[i] & 0xFF) as u8;
    }
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
