use poseidon::poseidon2::Poseidon2;
use utils::{get_issuing_country_from_mrz, get_nationality_from_mrz};

// Missing tests.
// Consider wrapping this in a constrained function that performs validation checks
// on this result, that are currently bleeding into both `check_nationality_exclusion`
// and `check_issuing_country_exclusion`.
// Edit: I've written such a function as an example, below, for your consideration.
// Returns the index of the item in the list which is closest (strictly greater than) the value.
// Even if there is a match in the list, it will return the index of the next-highest item
// in the list, because the intention is for this function to be used for _non-membership_ proofs.
unconstrained fn get_closest_index<let N: u32>(sorted_list: [u32; N], value: u32) -> i64 {
    let mut index: i64 = -1;
    for i in 0..N {
        if sorted_list[i] > value {
            index = i as i64;
            break;
        }
    }
    index
}

// Missing tests.
// Assumes the list is all 0`s after the first `0`.
// Consider wrapping this in a constrained function that performs validation checks
// on this result, that are currently bleeding into both `check_nationality_exclusion`
// and `check_issuing_country_exclusion`.
// Edit: I've written such a function as an example, below, for your consideration.
unconstrained fn get_last_index<let N: u32>(sorted_list: [u32; N]) -> i64 {
    let mut index: i64 = -1;
    for i in 0..N {
        if sorted_list[i] == 0 {
            index = (i - 1) as i64;
            break;
        }
    }
    index
}

// This was added after I did my first pass of this file, so some of my earlier comments might
// be stale (but most will still be good).
// This is technically checking that it's sorted up until the first zero, and zero thereafter.
pub fn check_country_list_sorted<let N: u32>(country_list: [u32; N]) -> bool {
    let mut result = true;
    let mut foundAZero = false;
    assert(country_list[0] != 0, "Country list cannot start with 0");
    for i in 0..N - 1 {
        // Zeroes mark the end of the list (i.e. start of the padding)
        // Consider replacing this line with:
        // if country_list[i + 1] == 0 {
        if !foundAZero & (country_list[i + 1] == 0) {
            foundAZero = true;
        }
        // If the current element is greater than the next element, then the list is not sorted
        // We also want to make sure there are no duplicates so we actually check greater than or equal.
        // Question: what's the motivation behind enabling invalid inputs to gracefully result in
        // a proof that can be verified? Usually, circuit designs just die and are unprovable if the inputs
        // aren't valid, since gracefully allowing invalid inputs costs constraints (and could be
        // harder to test).
        // I ask, because I was going to suggest "just use assert and don't bother returning false",
        // but then it dawned on me what you were trying to achieve.
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

// Missing tests.
// Strongly recommend tests for all of these branches, because it's difficult to follow.
// Also recommend _negative_ tests; at least one for every assert (and error messages to ensure the correct assertion is throwing).
// Tests should also be written to test for malicious values returned from the two unconstrained functions,
// perhaps by writing test-only versions where the results of unconstrained functions can be mocked.
//
// Edit after some consideration: I've proposed an alternative layout for this logic in some functions below,
// for your consideration. (They would need to be audited independently).
fn check_exclusion<let N: u32>(country_sum: u32, country_list: [u32; N]) {
    // Safety: since the list is assumed to be sorted in ascending order, we can get the index to check against
    // from an unconstrained function
    let closest_index = unsafe { get_closest_index(country_list, country_sum) };
    if closest_index == -1 {
        // Safety: get the index of the last element in the list that is not 0
        let last_index = unsafe { get_last_index(country_list) };
        assert(country_list[last_index as u32] > 0);
        if last_index < (N - 1) as i64 {
            // If there are still 0s after the last non-0 element,
            // then we need to check that the next element is 0
            assert_eq(country_list[last_index as u32 + 1], 0);
        }
        // If the index is -1, then the nationality sum is greater than all the elements in the list
        assert(country_list[last_index as u32] < country_sum);
    }
    // Assert that either the index is the first element of the list or the previous element is less than the nationality sum
    else if closest_index == 0 {
        // Assert that the country at the index is greater than the nationality sum
        assert(country_list[closest_index as u32] > country_sum);
    }
    // Cannot be done in a single if statement otherwise the second check will fail if closest_index is 0
    else if country_list[closest_index as u32 - 1] < country_sum {
        // Assert that the country at the index is greater than the nationality sum
        assert(country_list[closest_index as u32] > country_sum);
    } else {
        // Otherwise it should fail
        assert(false);
    }
    // If those two checks pass, then the nationality is not in the country list
}

// SUGGESTION to improve encapsulation and testability and auditability (but would need to be vetted).
// Would need tests.
// The current `check_exclusion` fn took me a while to work through, because it combines several checks.
// It would also be difficult to test the current `check_exclusion` thoroughly.
fn get_last_index_constrained<let N: u32>(sorted_list: [u32; N]) -> i64 {
    // Safety: the returned value is constrained below (with the assumptions that:
    // - the list is sorted
    // - every item after the first 0 is also 0
    // )
    let last_index = unsafe { get_last_index(sorted_list) };

    constrain_last_index(sorted_list, last_index);

    last_index
}

// Separated into a separate function, so that you can test your constraining logic
// with malicious `last_index` values, because you can't trust the returned value
// from `unsafe { get_last_index(sorted_list) }`
fn constrain_last_index<let N: u32>(sorted_list: [u32; N], last_index: i64) {
    if last_index != (N - 1) as i64 { // I.e. if it's not the last index in the array.
        // This will fail for last_index >= N - 1, due to out of bounds errors.
        
        // If there are still 0s after the last nonzero element,
        // then we need to check that the next element is 0
        assert_eq(sorted_list[last_index as u32 + 1], 0);
    }

    if last_index != -1 { // I.e. if it's not the first index in the array.
        // This will fail if last_index <= -2 also, due to out of bounds errors.
        assert(sorted_list[last_index as u32] != 0);
    }
}

// SUGGESTION to improve encapsulation and testability and auditability (but would need to be vetted).
// Would need tests.
fn check_exclusion_ALTERNATIVE<let N: u32>(sorted_list: [u32; N], value: u32) {
    // Safety: the returned value is constrained below, with the assumptions that:
    // - the list is sorted
    // - every item after the first 0 is also 0
    let closest_index_from_above = unsafe { get_closest_index(sorted_list, value) };

    constrain_closest_index(sorted_list, value, closest_index_from_above);
}

// Separated into a separate function, so that you can test your constraining logic
// with malicious `last_index` values, because you can't trust the returned value
// from `unsafe { get_closest_index(sorted_list) }`
fn constrain_closest_index<let N: u32>(sorted_list: [u32; N], value: u32, closest_index_from_above: i64) {
    // assert(closest_index_from_above < 0x80000000); // < 2^31 // technically needed, due to the `as u32` conversion below, but practically not a problem. 

    // Recommendation for a big block comment to show what's going on:
    //
    //    [b , d , f , h , j , l , n]
    //  ^  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^   ^     
    //  |  | | | | | | | | | | | | |   |      
    //  0  1 1 2 2 3 3 4 4 5 5 6 6 -1 -1 <-- the returned closest index (from above), if the
    //                                       `value` sits at or between these 
    //                                       elements in the array.
    //
    //    [b , d , f ,  h  ,  0  ,  0  ,  0]
    //  ^  ^ ^ ^ ^ ^ ^  ^  ^  ^  ^  ^  ^  ^   ^     
    //  |  | | | | | |  |  |  |  |  |  |  |   |      
    //  0  1 1 2 2 3 3 -1 -1 -1 -1 -1 -1 -1  -1 <-- the returned closest index (from above), if the
    //                                             `value` sits at or between these 
    //                                             elements in the array.
    //
    // if 0:
    //    assert(value < list[0]); // which implies the whole list is > value, since it's sorted. So value is not in the list. Great.
    // else if -1:
    //    // Then the `value` might still be at the "last" nonzero position in the list.
    //    // So we ensure that the `value` is > the last item, which implies the value is not in the list (since it's sorted). Great.
    //    Get the last_index (which is constrained to indeed be the last index)
    //    assert(list[last_index] < value);
    // else:
    //    // The `value` is somewhere in the middle of the first and last element of the list.
    //    // We don't want the `value` to _equal_ any item in the list, so we sandwich it between
    //    // two consecutive items in the list: 
    //    assert(list[closest_index_from_above - 1] < value);
    //    assert(value < list[closest_index_from_above]);
    //
    if closest_index_from_above == 0 {
        assert(value < sorted_list[0]);
    }
    else if closest_index_from_above == -1 {
        let last_index = get_last_index_constrained(sorted_list);
        assert(sorted_list[last_index as u32] < value);
    } else {
        let index = closest_index_from_above as u32;
        // Will fail with out of bounds errors if index >= N.
        assert(sorted_list[index - 1] < value);
        assert(value < sorted_list[index]);
    }
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
// Q: why is the country list u32's instead of u8's, if they represent individual bytes (u8's)?
pub fn check_nationality_exclusion<let N: u32>(dg1: [u8; 95], country_list: [u32; N]) {
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

// Missing tests.
/// Check if the issuing country from the MRZ is not in the country list
/// The list of countries is assumed to be sorted in ascending order
/// So it must come either from a public input that can be independently checked
/// or from a previous in-circuit check that the list is sorted
/// If the list is not sorted, the proof will fail to generate
pub fn check_issuing_country_exclusion<let N: u32>(dg1: [u8; 95], country_list: [u32; N]) {
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

// Visually inspected.
// Missing tests against some hard-coded param commitment somewhere.
// Inefficient packing. Instead of converting each u32 into its own field, you could more-tightly pack them.
// Why is the country_list for "exclusion" a `[u32; N]`, but the country list for "inclusion" is `[str<3>; N]`?
// Presumably both inclusion and exclusion could use the same `calculate_param_commitment` fn?
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
    let mut params = [0 as Field; N + 1];
    params[0] = proof_type as Field;
    for i in 1..N + 1 {
        params[i] = country_list[i - 1] as Field;
    }
    Poseidon2::hash(params, N + 1)
}

// Visually inspected.
// Missing tests against some hard-coded param commitment somewhere.
// Inconsistent vs the `inclusion-check/` version of `calculate_para_commitment_sha2`. Why is the country list a different type?
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
    let mut params = [0 as u8; N * 3 + 1];
    params[0] = proof_type;
    for i in 0..N {
        params[i * 3 + 1] = (country_list[i] >> 16) as u8;
        params[i * 3 + 2] = ((country_list[i] >> 8) & 0xFF) as u8;
        params[i * 3 + 3] = (country_list[i] & 0xFF) as u8;
    }
    let hash = sha256::sha256_var(params, (N * 3 + 1) as u64);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}

// Consider adding extra tests that have full country lists (instead of 0s at the end),
// to ensure the `check_country_list_sorted` function works for that edge case.
#[test]
fn test_country_list_sorting_check() {
    // List in descending order, so not sorted in ascending order
    let country_list: [u32; 6] = [4608578, 4608577, 4608579, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List in ascending order
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, true);

    // List with duplicates
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608579, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List not in a particular order
    let country_list: [u32; 6] = [4608577, 4608579, 4608578, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);
}

#[test(should_fail_with = "Country list cannot contain 0s before the last non-0 element")]
fn test_country_list_sorting_fail_with_0_in_middle() {
    let country_list: [u32; 6] = [4608577, 0, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test(should_fail_with = "Country list cannot start with 0")]
fn test_country_list_sorting_fail_when_starts_with_0() {
    let country_list: [u32; 6] = [0, 4608577, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test]
fn test_exclusion_check_pass() {
    let country_list: [u32; 6] = [4608577, 4608582, 4608590, 0, 0, 0];
    check_exclusion(4608576, country_list);
    check_exclusion(4608580, country_list);
    check_exclusion(4608589, country_list);
    check_exclusion(4608591, country_list);
}

#[test(should_fail)]
fn test_exclusion_check_fail() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608577, country_list);
}

#[test(should_fail)]
fn test_exclusion_check_fail_2() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608578, country_list);
}
