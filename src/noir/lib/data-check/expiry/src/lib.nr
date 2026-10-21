use date::Date;
use utils::{
    constants::MAX_DOCUMENT_VALIDITY_YEARS,
    get_expiry_date_from_mrz,
    types::{DG1Data, YYMMDDDate},
};

pub mod tests;

pub fn check_expiry(dg1: DG1Data, current_date_timestamp: u64) {
    let expiry_date_bytes = get_expiry_date_from_mrz(dg1);
    check_expiry_from_date(expiry_date_bytes, current_date_timestamp);
}

pub fn check_expiry_from_date(expiry_date_bytes: YYMMDDDate, current_date_timestamp: u64) {
    let current_date = Date::from_timestamp(current_date_timestamp);

    // Resolve the 2-digit MRZ year against the shared expiry pivot - must match
    // compare::date::get_expiry_date so the same bytes can't resolve to two centuries.
    let threshold_year = current_date.add_years(MAX_DOCUMENT_VALIDITY_YEARS);

    let expiry_date = Date::from_bytes_short_year(expiry_date_bytes, threshold_year);

    assert(current_date.lt(expiry_date), "Document is expired");
}
