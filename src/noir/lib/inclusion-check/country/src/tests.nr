use super::{check_issuing_country_inclusion, check_nationality_inclusion};
use utils::constants::SAMPLE_DG1;

fn pad_country_list<let N: u32>(country_list: [str<3>; N]) -> [str<3>; 200] {
    let mut padded_country_list: [str<3>; 200] = ["\0\0\0"; 200];
    for i in 0..N {
        padded_country_list[i] = country_list[i];
    }
    padded_country_list
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
