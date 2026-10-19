use super::check_expiry;
use date::Date;
use utils::constants::{DG1_TO_MRZ_OFFSET, PASSPORT_MRZ_EXPIRY_DATE_INDEX, SAMPLE_DG1};
use utils::types::DG1Data;

// Build a passport DG1 with a custom 6-byte "YYMMDD" expiry, reusing SAMPLE_DG1 for the
// rest. check_expiry reads only the expiry slice, so MRZ check digits don't matter here.
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

// Regression (expiry-pivot consistency finding): a genuinely-valid long-validity
// document must not be rejected. Expiry 2060 at current 2026 is a ~34-year document;
// under the old +30 pivot its YY (60) resolved to 1960 and check_expiry wrongly reported
// "Document is expired". With the shared MAX_DOCUMENT_VALIDITY_YEARS (50) pivot it
// resolves to 2060 and correctly passes.
#[test]
fn test_check_expiry_long_validity() {
    let dg1: [u8; 95] = dg1_with_expiry("600101".as_bytes());
    check_expiry(dg1, Date::new(2026, 6, 25).to_timestamp());
}
