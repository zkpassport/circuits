use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{
    get_array_slice, get_mrz_from_dg1, ID_CARD_MRZ_BIRTHDATE_INDEX, is_id_card,
    PASSPORT_MRZ_BIRTHDATE_INDEX, PROOF_TYPE_AGE,
};

// P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<PA1234567_AUS881112_M300101_<CYBERCITY<<<<<<
global SAMPLE_DG1: [u8; 95] = [
    0x61, 0x5B, 0x5F, 0x1F, 0x58, 80, 60, 65, 85, 83, 83, 73, 76, 86, 69, 82, 72, 65, 78, 68, 60,
    60, 74, 79, 72, 78, 78, 89, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    60, 60, 60, 60, 80, 65, 49, 50, 51, 52, 53, 54, 55, 95, 65, 85, 83, 56, 56, 49, 49, 49, 50, 95,
    77, 51, 48, 48, 49, 48, 49, 95, 60, 67, 89, 66, 69, 82, 67, 73, 84, 89, 60, 60, 60, 60, 60, 60,
    0, 0,
];

fn get_birthdate(dg1: [u8; 95], timestamp: u64) -> Date {
    let mut birthdate_bytes = [0 as u8; 6];
    let mrz = get_mrz_from_dg1(dg1);

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
        // Adding 1 and using lt, so that max_age is inclusive up to the very last day before reaching max_age + 1
        assert(
            current_date.lt(birthdate.add_years(max_age as u32 + 1)),
            "Age is not below or equal to max age",
        );
    } else {
        assert(min_age <= max_age, "Min age must be less than or equal to max age");

        assert(
            current_date.gte(birthdate.add_years(min_age as u32)),
            "Age is not above or equal to min age",
        );
        // This way if max_age = min_age, the proof will be valid whenever the age
        // is equal to min_age = max_age
        assert(
            current_date.lt(birthdate.add_years((max_age + 1) as u32)),
            "Age is not below or equal to max age",
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

#[test]
fn test_get_birthdate() {
    let birthdate = get_birthdate(SAMPLE_DG1, 1757609123);
    assert_eq(birthdate, Date::from_timestamp(595296000));
}

#[test]
fn test_compare_age_range() {
    let dg1 = SAMPLE_DG1;
    let min_age = 35;
    let max_age = 37;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 36;
    let max_age = 36;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_greater_than_or_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 36;
    let max_age = 0;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should pass because the age just reached 37
#[test]
fn test_compare_age_greater_than_or_equal_edge() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 0;
    // 2025-11-12
    let timestamp = 1762905600;
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should fail because the age is one day away from 37
#[test(should_fail_with = "Age is not above or equal to min age")]
fn test_compare_age_greater_than_or_equal_fail() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 0;
    // 2025-11-11
    let timestamp = 1762819200;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_less_than_or_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should pass because the birthdate is the next day,
// so the age is still 36
#[test]
fn test_compare_age_less_than_or_equal_edge() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    // 2025-11-11
    let timestamp = 1762819200;
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should fail because the age is now 37
#[test(should_fail_with = "Age is not below or equal to max age")]
fn test_compare_age_less_than_or_equal_fail() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    // 2025-11-12
    let timestamp = 1762905600;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Min age must be less than or equal to max age")]
fn test_compare_age_min_greater_than_max() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 36;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Either min or max age must be non-zero")]
fn test_compare_age_min_and_max_zero() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 0;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Age must be less than 100")]
fn test_compare_age_max_greater_than_100() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 100;
    let timestamp = 1757609123;
    compare_age(dg1, min_age, max_age, timestamp);
}
