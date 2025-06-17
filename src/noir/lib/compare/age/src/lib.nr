use date::Date;
use std::hash::poseidon2::Poseidon2;
use utils::dg1::DG1;
use utils::packing::pack_be_bytes_into_field;
use utils::PROOF_TYPE_AGE;
use utils::types::DG1Data;

pub fn compare_age(dg1: DG1Data, min_age: u8, max_age: u8, current_date_bytes: [u8; 8]) {
    // Restrict the age to be less than 100 as the dg1 birthdate only encodes
    // two digits for the year
    // TODO: Add support for dg11 to support 100+
    assert((max_age < 100) & (min_age < 100), "Age must be less than 100");

    let dg1_data = DG1::new(dg1);
    let birthdate: Date = dg1_data.get_birthdate(current_date_bytes);

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    assert((min_age != 0) | (max_age != 0));

    if (min_age != 0) & (max_age == 0) {
        // Check if age is above min age
        // The minimum age is more likely to be inclusive, so we use gte
        assert(current_date.gte(birthdate.add_years(min_age as u32)));
    } else if (max_age != 0) & (min_age == 0) {
        // Check if age is below max age
        // The maximum age is more likely to be exclusive, so we use lt
        assert(current_date.lt(birthdate.add_years(max_age as u32)));
    } else {
        assert(min_age <= max_age);

        assert(current_date.gte(birthdate.add_years(min_age as u32)));
        // This way if max_age = min_age, the proof will be valid whenever the age
        // is equal to min_age = max_age
        assert(current_date.lt(birthdate.add_years((max_age + 1) as u32)));
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
    current_date: str<8>,
    min_age_required: u8,
    max_age_required: u8,
) -> Field {
    let mut params = [0 as Field; 11];
    params[0] = PROOF_TYPE_AGE as Field;
    let current_date_bytes = current_date.as_bytes();
    for i in 1..9 {
        params[i] = current_date_bytes[i - 1] as Field;
    }
    params[9] = min_age_required as Field;
    params[10] = max_age_required as Field;
    Poseidon2::hash(params, 11)
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
    current_date: str<8>,
    min_age_required: u8,
    max_age_required: u8,
) -> Field {
    let mut params = [0 as u8; 11];
    params[0] = PROOF_TYPE_AGE;
    let current_date_bytes = current_date.as_bytes();
    for i in 1..9 {
        params[i] = current_date_bytes[i - 1];
    }
    params[9] = min_age_required;
    params[10] = max_age_required;
    let hash = sha256::sha256_var(params, 11);
    pack_be_bytes_into_field::<32, 31>(hash)
}
