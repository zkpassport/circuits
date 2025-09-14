use date::Date;
use utils::{
    constants::{ID_CARD_MRZ_EXPIRY_DATE_INDEX, PASSPORT_MRZ_EXPIRY_DATE_INDEX, YYMMDD_DATE_LENGTH},
    get_array_slice,
    get_mrz_from_dg1,
    is_id_card,
    types::DG1Data,
};

pub mod tests;

pub fn check_expiry(dg1: DG1Data, current_date_timestamp: u64) {
    let current_date = Date::from_timestamp(current_date_timestamp);

    let mrz = get_mrz_from_dg1(dg1);

    // We base the threshold year for the expiry date on the current date plus 30 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 30 years we should be safe
    let threshold_year = current_date.add_years(30);

    let mut expiry_date_bytes = [0 as u8; YYMMDD_DATE_LENGTH];

    if is_id_card(dg1) {
        expiry_date_bytes =
            get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, ID_CARD_MRZ_EXPIRY_DATE_INDEX);
    } else {
        expiry_date_bytes =
            get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, PASSPORT_MRZ_EXPIRY_DATE_INDEX);
    }

    let expiry_date = Date::from_bytes_short_year(expiry_date_bytes, threshold_year);

    assert(current_date.lt(expiry_date), "Document is expired");
}
