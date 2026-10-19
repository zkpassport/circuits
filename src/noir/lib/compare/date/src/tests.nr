use super::{compare_date, get_birthdate, get_expiry_date};
use date::Date;
use utils::constants::{DG1_TO_MRZ_OFFSET, PASSPORT_MRZ_EXPIRY_DATE_INDEX, SAMPLE_DG1};
use utils::types::DG1Data;

// Build a passport DG1 with a custom 6-byte "YYMMDD" expiry, reusing SAMPLE_DG1 for
// every other field. (These helpers read only the expiry slice, so MRZ check digits
// don't matter here.)
fn dg1_with_expiry(yymmdd: [u8; 6]) -> DG1Data {
    let mut dg1 = SAMPLE_DG1;
    for i in 0..6 {
        dg1[DG1_TO_MRZ_OFFSET + PASSPORT_MRZ_EXPIRY_DATE_INDEX + i] = yymmdd[i];
    }
    dg1
}

#[test]
fn test_get_birthdate() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2025, 9, 12).to_timestamp());
    assert_eq(birthdate, Date::new(1988, 11, 12));
}

#[test]
fn test_get_birthdate_wrong_century() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2088, 1, 1).to_timestamp());
    // If passed a date after 100 years (ignoring the day and month) after the birthdate, it will get the wrong century
    assert_eq(birthdate, Date::new(2088, 11, 12));
}

#[test]
fn test_get_birthdate_edge_current_date() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2087, 12, 31).to_timestamp());
    // Just one year away from being 100 years after the birthdate
    // so it will still be the correct century
    assert_eq(birthdate, Date::new(1988, 11, 12));
}

#[test]
fn test_get_expiry_date() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(2025, 9, 12).to_timestamp());
    assert_eq(expiry_date, Date::new(2030, 1, 1));
}

#[test]
fn test_get_expiry_date_wrong_century() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(1975, 1, 1).to_timestamp());
    // The pivot is current + MAX_DOCUMENT_VALIDITY_YEARS (50). When the current date is
    // more than 50 years before the expiry (expiry 2030, current 1975), the YY resolves
    // to the previous century.
    assert_eq(expiry_date, Date::new(1930, 1, 1));
}

#[test]
fn test_get_expiry_date_edge_current_date() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(1980, 1, 1).to_timestamp());
    // Exactly 50 years before the expiry (the pivot boundary), so still the correct century.
    assert_eq(expiry_date, Date::new(2030, 1, 1));
}

// Regression (expiry-pivot consistency finding): a long-validity document whose real
// expiry falls in the old 20/30-year overlap window must resolve to the correct future
// century. Expiry 2051 at current 2026 resolves to 2051; under the old +20 pivot
// get_expiry_date returned 1951 while check_expiry (at +30) saw 2051 - the divergence
// this fix removes. Both helpers now share MAX_DOCUMENT_VALIDITY_YEARS.
#[test]
fn test_get_expiry_date_overlap_window_consistent() {
    let dg1 = dg1_with_expiry("510115".as_bytes());
    let expiry_date = get_expiry_date(dg1, Date::new(2026, 6, 25).to_timestamp());
    assert_eq(expiry_date, Date::new(2051, 1, 15));
}

#[test]
fn test_compare_date_range() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2020, 1, 1);
    let max_date = Date::new(2040, 1, 1);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not above or equal to min date")]
fn test_compare_date_range_min_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 2);
    let max_date = Date::new(2030, 1, 3);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not below or equal to max date")]
fn test_compare_date_range_max_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2029, 12, 29);
    let max_date = Date::new(2029, 12, 31);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test]
fn test_compare_date_equal() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 1);
    let max_date = Date::new(2030, 1, 1);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test]
fn test_compare_date_greater_than_or_equal() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2029, 12, 31);
    compare_date(date, min_date.to_timestamp(), 0, 1970);
}

#[test(should_fail_with = "Date is not above or equal to min date")]
fn test_compare_date_greater_than_or_equal_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 2);
    compare_date(date, min_date.to_timestamp(), 0, 1970);
}

#[test]
fn test_compare_date_less_than_or_equal() {
    let date = Date::new(2030, 1, 1);
    let max_date = Date::new(2030, 1, 2);
    compare_date(date, 0, max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not below or equal to max date")]
fn test_compare_date_less_than_or_equal_fail() {
    let date = Date::new(2030, 1, 1);
    let max_date = Date::new(2029, 12, 31);
    compare_date(date, 0, max_date.to_timestamp(), 1970);
}
