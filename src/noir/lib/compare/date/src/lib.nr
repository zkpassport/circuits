use date::Date;
use std::hash::poseidon2::Poseidon2;
use utils::packing::pack_be_bytes_into_field;

pub fn compare_date(date_to_compare: Date, min_date_bytes: [u8; 8], max_date_bytes: [u8; 8]) {
    assert((min_date_bytes != [49; 8]) | (max_date_bytes != [49; 8]));

    let min_date = Date::from_bytes_long_year(min_date_bytes);
    let max_date = Date::from_bytes_long_year(max_date_bytes);

    if (min_date_bytes != [49; 8]) & (max_date_bytes == [49; 8]) {
        // The minimum date is more likely to be inclusive, so we use gte
        assert(date_to_compare.gte(min_date));
    } else if (max_date_bytes != [49; 8]) & (min_date_bytes == [49; 8]) {
        // The maximum date is more likely to be inclusive, so we use lte
        assert(date_to_compare.lte(max_date));
    } else {
        assert(min_date.lte(max_date));

        // Check if birthdate is within the range
        assert(date_to_compare.gte(min_date));
        assert(date_to_compare.lte(max_date));
    }
}

/// Calculate the commitment of the current date, min date and max date using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `current_date`: The current date
/// * `min_date`: The minimum date
/// * `max_date`: The maximum date
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min date and max date
pub fn calculate_param_commitment(
    proof_type: u8,
    current_date: str<8>,
    min_date: str<8>,
    max_date: str<8>,
) -> Field {
    let mut params = [0 as Field; 25];
    params[0] = proof_type as Field;
    let current_date_bytes = current_date.as_bytes();
    for i in 1..9 {
        params[i] = current_date_bytes[i - 1] as Field;
    }
    let min_date_bytes = min_date.as_bytes();
    for i in 9..17 {
        params[i] = min_date_bytes[i - 9] as Field;
    }
    let max_date_bytes = max_date.as_bytes();
    for i in 17..25 {
        params[i] = max_date_bytes[i - 17] as Field;
    }
    Poseidon2::hash(params, 25)
}

/// Calculate the commitment of the current date, min date and max date using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `current_date`: The current date
/// * `min_date`: The minimum date
/// * `max_date`: The maximum date
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min date and max date
pub fn calculate_param_commitment_sha2(
    proof_type: u8,
    current_date: str<8>,
    min_date: str<8>,
    max_date: str<8>,
) -> Field {
    let mut params = [0 as u8; 25];
    params[0] = proof_type;
    let current_date_bytes = current_date.as_bytes();
    for i in 1..9 {
        params[i] = current_date_bytes[i - 1];
    }
    let min_date_bytes = min_date.as_bytes();
    for i in 9..17 {
        params[i] = min_date_bytes[i - 9];
    }
    let max_date_bytes = max_date.as_bytes();
    for i in 17..25 {
        params[i] = max_date_bytes[i - 17];
    }
    let hash = sha256::sha256_var(params, 25);
    pack_be_bytes_into_field::<32, 31>(hash)
}
