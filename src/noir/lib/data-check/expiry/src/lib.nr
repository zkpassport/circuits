use date::Date;
use utils::{
    get_array_slice, get_mrz_from_dg1, ID_CARD_MRZ_EXPIRY_DATE_INDEX, is_id_card,
    PASSPORT_MRZ_EXPIRY_DATE_INDEX,
};

pub fn check_expiry(dg1: [u8; 95], current_date_timestamp: u64) {
    // Date library not audited.
    let current_date = Date::from_timestamp(current_date_timestamp);

    let mrz = get_mrz_from_dg1(dg1);

    // Recommend defining "threshold year" here. From clicking through the code, 
    // it seems "threshold_year" establishes 0 mod 100 for the YY date format?
    // So the YYYY of `expiry_date` chooses between 19XX and 20XX based on the threshold_year.

    // We base the threshold year for the expiry date on the current date plus 30 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 30 years we should be safe
    let threshold_year = current_date.add_years(30); // Consider using global instead of magic number

    let mut expiry_date_bytes = [0 as u8; 6]; // Consider using global instead of magic number 

    // This logic to extract bytes could potentially live in utils.
    if is_id_card(dg1) {
        expiry_date_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6, // Consider using global instead of magic number 6
        );
    } else {
        expiry_date_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6,
        );
    }

    let expiry_date = Date::from_bytes_short_year(expiry_date_bytes, threshold_year);

    assert(current_date.lt(expiry_date), "Document is expired");
}
