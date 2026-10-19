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

    // Resolve the 2-digit MRZ year against the shared expiry pivot. This MUST match the
    // pivot used by compare::date::get_expiry_date (both read MAX_DOCUMENT_VALIDITY_YEARS)
    // so the same bytes can never resolve to two different centuries within one proof.
    let threshold_year = current_date.add_years(MAX_DOCUMENT_VALIDITY_YEARS);

    let expiry_date = Date::from_bytes_short_year(expiry_date_bytes, threshold_year);

    // NOTE: strict `lt` is intentional - the document is treated as expired *on* its
    // expiry date (valid strictly before it), which `test_check_expiry_expired` pins.
    // If the "valid through the expiry date" reading is
    // preferred, switch to `lte` and update the test.
    assert(current_date.lt(expiry_date), "Document is expired");
}
