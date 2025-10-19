use super::{check_issuing_country_inclusion, check_nationality_inclusion, unsafe_get_index};
use utils::{constants::{EMPTY_ALPHA3_COUNTRY_CODE, SAMPLE_DG1}, types::Alpha3CountryCode};

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
