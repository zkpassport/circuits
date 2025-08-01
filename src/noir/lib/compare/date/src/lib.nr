use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{
    get_array_slice, get_mrz_from_dg1, ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_EXPIRY_DATE_INDEX,
    is_id_card, PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_EXPIRY_DATE_INDEX,
};

fn get_date<let INDEX: u32>(dg1: [u8; 95], threshold_year_bytes: [u8; 8]) -> Date {
    let mrz = get_mrz_from_dg1(dg1);

    let date_bytes = get_array_slice(mrz, INDEX, INDEX + 6);

    // Create a Date object from the date using the current date as
    // the pivot year to differentiate between 20th and 21st centuries
    // as the format is "YYMMDD"
    Date::from_bytes_short_year(
        date_bytes,
        [threshold_year_bytes[2], threshold_year_bytes[3]],
    )
}

pub fn get_birthdate(dg1: [u8; 95], current_date: [u8; 8]) -> Date {
    let mut birthdate = Date::new(1, 1, 1);

    // Get the slice of the MRZ representing the birthdate
    if is_id_card(dg1) {
        birthdate = get_date::<ID_CARD_MRZ_BIRTHDATE_INDEX>(dg1, current_date);
    } else {
        birthdate = get_date::<PASSPORT_MRZ_BIRTHDATE_INDEX>(dg1, current_date);
    }

    birthdate
}

pub fn get_expiry_date(dg1: [u8; 95], current_date: [u8; 8]) -> Date {
    let mut expiry_date = Date::new(1, 1, 1);

    // We base the threshold year for the expiry date on the current date plus 20 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 20 years we should be safe
    let threshold_year = Date::from_bytes_long_year(current_date).add_years(20);
    let threshold_year_bytes = threshold_year.to_bytes();

    // Get the slice of the MRZ representing the expiry date
    if is_id_card(dg1) {
        expiry_date = get_date::<ID_CARD_MRZ_EXPIRY_DATE_INDEX>(dg1, threshold_year_bytes);
    } else {
        expiry_date = get_date::<PASSPORT_MRZ_EXPIRY_DATE_INDEX>(dg1, threshold_year_bytes);
    }

    expiry_date
}

pub fn compare_date(date_to_compare: Date, min_date_bytes: [u8; 8], max_date_bytes: [u8; 8]) {
    assert(
        (min_date_bytes != [49; 8]) | (max_date_bytes != [49; 8]),
        "Either min or max date must be non-zero",
    );

    let min_date = Date::from_bytes_long_year(min_date_bytes);
    let max_date = Date::from_bytes_long_year(max_date_bytes);

    if (min_date_bytes != [49; 8]) & (max_date_bytes == [49; 8]) {
        // The minimum date is more likely to be inclusive, so we use gte
        assert(date_to_compare.gte(min_date), "Date is not above or equal to min date");
    } else if (max_date_bytes != [49; 8]) & (min_date_bytes == [49; 8]) {
        // The maximum date is more likely to be inclusive, so we use lte
        assert(date_to_compare.lte(max_date), "Date is not below or equal to max date");
    } else {
        assert(min_date.lte(max_date), "Min date must be less than or equal to max date");

        // Check if birthdate is within the range
        assert(date_to_compare.gte(min_date), "Date is not above or equal to min date");
        assert(date_to_compare.lte(max_date), "Date is not below or equal to max date");
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
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
