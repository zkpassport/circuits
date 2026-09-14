use super::{
    check_country_list_padding, check_issuing_country_inclusion, check_nationality_inclusion,
    unsafe_get_index,
};
use utils::{
    constants::{
        DG1_TO_MRZ_OFFSET, EMPTY_ALPHA3_COUNTRY_CODE, PASSPORT_MRZ_ISSUING_COUNTRY_INDEX,
        PASSPORT_MRZ_NATIONALITY_INDEX, SAMPLE_DG1,
    },
    types::Alpha3CountryCode,
};

fn pad_country_list<let N: u32>(country_list: [Alpha3CountryCode; N]) -> [Alpha3CountryCode; 200] {
    let mut padded_country_list: [Alpha3CountryCode; 200] = [EMPTY_ALPHA3_COUNTRY_CODE; 200];
    for i in 0..N {
        padded_country_list[i] = country_list[i];
    }
    padded_country_list
}

#[test]
fn test_get_index() {
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    let index = unsafe { unsafe_get_index(country_list, "AUS".as_bytes()) };
    assert_eq(index, 0);
    let index = unsafe { unsafe_get_index(country_list, "NZL".as_bytes()) };
    assert_eq(index, 1);
    let index = unsafe { unsafe_get_index(country_list, "USA".as_bytes()) };
    assert_eq(index, 2);
    let index = unsafe { unsafe_get_index(country_list, "FRA".as_bytes()) };
    assert_eq(index, -1);
    let index = unsafe { unsafe_get_index(country_list, EMPTY_ALPHA3_COUNTRY_CODE.as_bytes()) };
    assert_eq(index, -1);
}

#[test]
fn test_check_nationality_inclusion() {
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    check_nationality_inclusion(SAMPLE_DG1, country_list);
}

#[test(should_fail_with = "Country not found in the list")]
fn test_check_nationality_inclusion_fail() {
    let country_list = pad_country_list(["FRA", "NZL", "USA"]);
    check_nationality_inclusion(SAMPLE_DG1, country_list);
}

// Regression: a \0\0\0 nationality must not "match" the list's empty padding and
// thereby prove inclusion in any list.
#[test(should_fail_with = "Nationality is empty")]
fn test_check_nationality_inclusion_fail_empty_nationality() {
    let mut dg1 = SAMPLE_DG1;
    for i in 0..3 {
        dg1[DG1_TO_MRZ_OFFSET + PASSPORT_MRZ_NATIONALITY_INDEX + i] = 0;
    }
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    check_nationality_inclusion(dg1, country_list);
}

#[test]
fn test_check_issuing_country_inclusion() {
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    check_issuing_country_inclusion(SAMPLE_DG1, country_list);
}

#[test(should_fail_with = "Country not found in the list")]
fn test_check_issuing_country_inclusion_fail() {
    let country_list = pad_country_list(["FRA", "NZL", "USA"]);
    check_issuing_country_inclusion(SAMPLE_DG1, country_list);
}

// Regression: a \0\0\0 issuing country must not "match" the list's empty padding.
#[test(should_fail_with = "Issuing country is empty")]
fn test_check_issuing_country_inclusion_fail_empty_issuing_country() {
    let mut dg1 = SAMPLE_DG1;
    for i in 0..3 {
        dg1[DG1_TO_MRZ_OFFSET + PASSPORT_MRZ_ISSUING_COUNTRY_INDEX + i] = 0;
    }
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    check_issuing_country_inclusion(dg1, country_list);
}

#[test]
fn test_check_country_list_padding_padded() {
    let country_list = pad_country_list(["AUS", "NZL", "USA"]);
    check_country_list_padding(country_list);
}

#[test]
fn test_check_country_list_padding_full_list() {
    let country_list: [Alpha3CountryCode; 3] = ["AUS", "NZL", "USA"];
    check_country_list_padding(country_list);
}

#[test]
fn test_check_country_list_padding_fully_empty() {
    let country_list: [Alpha3CountryCode; 3] =
        [EMPTY_ALPHA3_COUNTRY_CODE, EMPTY_ALPHA3_COUNTRY_CODE, EMPTY_ALPHA3_COUNTRY_CODE];
    check_country_list_padding(country_list);
}

#[test(should_fail_with = "Country list cannot contain country codes after the padding")]
fn test_check_country_list_padding_injection_after_padding() {
    let country_list: [Alpha3CountryCode; 4] =
        ["AUS", EMPTY_ALPHA3_COUNTRY_CODE, "USA", EMPTY_ALPHA3_COUNTRY_CODE];
    check_country_list_padding(country_list);
}

#[test(should_fail_with = "Country list cannot contain country codes after the padding")]
fn test_check_country_list_padding_starts_with_empty() {
    let country_list: [Alpha3CountryCode; 3] =
        [EMPTY_ALPHA3_COUNTRY_CODE, "AUS", EMPTY_ALPHA3_COUNTRY_CODE];
    check_country_list_padding(country_list);
}

#[test(should_fail_with = "Country list cannot contain country codes after the padding")]
fn test_check_nationality_inclusion_fail_injection_after_padding() {
    let mut country_list: [Alpha3CountryCode; 200] = [EMPTY_ALPHA3_COUNTRY_CODE; 200];
    country_list[0] = "AUS";
    // Inject a country code after the padding has started
    country_list[5] = "USA";
    check_nationality_inclusion(SAMPLE_DG1, country_list);
}

#[test(should_fail_with = "Country list cannot contain country codes after the padding")]
fn test_check_issuing_country_inclusion_fail_injection_after_padding() {
    let mut country_list: [Alpha3CountryCode; 200] = [EMPTY_ALPHA3_COUNTRY_CODE; 200];
    country_list[0] = "AUS";
    // Inject a country code after the padding has started
    country_list[5] = "USA";
    check_issuing_country_inclusion(SAMPLE_DG1, country_list);
}
