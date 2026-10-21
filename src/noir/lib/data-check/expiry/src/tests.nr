use super::check_expiry;
use date::Date;
use utils::constants::{DG1_TO_MRZ_OFFSET, PASSPORT_MRZ_EXPIRY_DATE_INDEX, SAMPLE_DG1};
use utils::types::DG1Data;

// Passport DG1 with a custom "YYMMDD" expiry, reusing SAMPLE_DG1 for the rest (only the
// expiry slice is read, so check digits don't matter).
fn dg1_with_expiry(yymmdd: [u8; 6]) -> DG1Data {
    let mut dg1: [u8; 95] = SAMPLE_DG1;
    for i in 0..6 {
        dg1[DG1_TO_MRZ_OFFSET + PASSPORT_MRZ_EXPIRY_DATE_INDEX + i] = yymmdd[i];
    }
    dg1
}

#[test]
fn test_check_expiry() {
    let current_date = Date::new(2025, 9, 12);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}

#[test]
fn test_check_expiry_edge() {
    // This one day before the expiry date, so it is still valid
    let current_date = Date::new(2029, 12, 31);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}

#[test(should_fail_with = "Document is expired")]
fn test_check_expiry_expired() {
    // The expiry date is 2030-1-1 so here it is expired
    let current_date = Date::new(2030, 1, 1);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}

// Regression (expiry-pivot consistency): a valid long-validity document within the pivot
// margin must not be rejected. Expiry 2055 at current 2026 (~29y) resolves to 2055 and
// passes.
#[test]
fn test_check_expiry_long_validity() {
    let dg1: [u8; 95] = dg1_with_expiry("550101".as_bytes());
    check_expiry(dg1, Date::new(2026, 6, 25).to_timestamp());
}
