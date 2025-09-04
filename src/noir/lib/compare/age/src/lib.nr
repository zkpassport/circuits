use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{
    get_array_slice, get_mrz_from_dg1, ID_CARD_MRZ_BIRTHDATE_INDEX, is_id_card,
    PASSPORT_MRZ_BIRTHDATE_INDEX, PROOF_TYPE_AGE,
};

fn get_birthdate(dg1: [u8; 95], timestamp: u64) -> Date {
    let mut birthdate_bytes = [0 as u8; 6];
    let mrz = get_mrz_from_dg1(dg1);

    // There's `get_dob_from_mrz` in utils; consider using that.
    // Get the slice of the MRZ representing the birthdate
    if is_id_card(dg1) {
        birthdate_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_BIRTHDATE_INDEX,
            ID_CARD_MRZ_BIRTHDATE_INDEX + 6,
        );
    } else {
        // Otherwise it's an ID card
        birthdate_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_BIRTHDATE_INDEX,
            PASSPORT_MRZ_BIRTHDATE_INDEX + 6,
        );
    }

    // Date library not audited.
    let current_date = Date::from_timestamp(timestamp);

    // Create a Date object from the birthdate using the current date as
    // the pivot year to differentiate between 20th and 21st centuries
    // as the format is "YYMMDD"
    Date::from_bytes_short_year(birthdate_bytes, current_date)
}

pub fn compare_age(dg1: [u8; 95], min_age: u8, max_age: u8, timestamp: u64) {
    // Restrict the age to be less than 100 as the dg1 birthdate only encodes
    // two digits for the year
    // TODO: Add support for dg11 to support 100+
    assert((max_age < 100) & (min_age < 100), "Age must be less than 100");

    let birthdate: Date = get_birthdate(dg1, timestamp);

    let current_date = Date::from_timestamp(timestamp);

    assert((min_age != 0) | (max_age != 0), "Either min or max age must be non-zero");

    if (min_age != 0) & (max_age == 0) {
        // Check if age is above min age
        // The minimum age is more likely to be inclusive, so we use gte
        assert(
            current_date.gte(birthdate.add_years(min_age as u32)),
            "Age is not above or equal to min age",
        );
    } else if (max_age != 0) & (min_age == 0) {
        // Check if age is below max age
        // The maximum age is more likely to be exclusive, so we use lt
        // Danger: from a quick glance at `add_years`, there might be a bug. `add_years` will result in a non-existent (invalid) date if the person was born on Feb 29th, 
        // when adding a number of years that is not a multiple of 4 (or when landing on century years that are not a multiple of 400).
        assert(current_date.lt(birthdate.add_years(max_age as u32)), "Age is not below max age");
    } else {
        // I don't understand the approach for `max_age` in this `else` block. It's inconsistent with the previous
        // `else if` block's approach to comparing against the max_age.
        // It says in the zkpassport docs:
        //     "The lower bound for age comparison is inclusive, but the upper bound is exclusive. 
        //      Hence, the available operators for age are gte (greater than or equal to) and lt (less than)."
        // Given that intention, I think this function should disallow `min_age = max_age`, and enforce
        // a strict `<`.
        assert(min_age <= max_age, "Min age must be less than or equal to max age");

        assert(
            current_date.gte(birthdate.add_years(min_age as u32)),
            "Age is not above or equal to min age",
        );

        // If the max_age is specified as 50, based on the comments and docs, you only want to 
        // allow someone who is <= 49 (hasn't had their 50th birthday yet). But this function will allow
        // someone who has long been age 50 for ~364 days.
        // This way if max_age = min_age, the proof will be valid whenever the age
        // is equal to min_age = max_age
        assert(
            current_date.lt(birthdate.add_years((max_age + 1) as u32)),
            "Age is not below max age",
        );
    }
}

/// Calculate the commitment of the current date, min age and max age using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `current_date`: The current date
/// * `min_age_required`: The minimum age required
/// * `max_age_required`: The maximum age required
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min age and max age
pub fn calculate_param_commitment(
    timestamp: u64,
    min_age_required: u8,
    max_age_required: u8,
) -> Field {
    let mut params = [0 as Field; 4];
    params[0] = PROOF_TYPE_AGE as Field;
    params[1] = timestamp as Field;
    params[2] = min_age_required as Field;
    params[3] = max_age_required as Field;
    Poseidon2::hash(params, 4)
}

/// Calculate the commitment of the current date, min age and max age using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `current_date`: The current date
/// * `min_age_required`: The minimum age required
/// * `max_age_required`: The maximum age required
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min age and max age
pub fn calculate_param_commitment_sha2(
    timestamp: u64,
    min_age_required: u8,
    max_age_required: u8,
) -> Field {
    let mut params = [0 as u8; 11];
    params[0] = PROOF_TYPE_AGE;
    let timestamp_bytes: [u8; 8] = (timestamp as Field).to_be_bytes();
    for i in 1..9 {
        params[i] = timestamp_bytes[i - 1];
    }
    params[9] = min_age_required;
    params[10] = max_age_required;
    let hash = sha256::sha256_var(params, 11);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
