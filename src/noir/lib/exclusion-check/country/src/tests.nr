use super::{check_country_list_sorted, check_exclusion};

#[test]
fn test_country_list_sorting_check() {
    // List in descending order, so not sorted in ascending order
    let country_list: [u32; 6] = [4608578, 4608577, 4608576, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List in ascending order
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, true);

    // List with duplicates
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608579, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List not in a particular order
    let country_list: [u32; 6] = [4608577, 4608579, 4608578, 0, 0, 0];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);
}

#[test(should_fail_with = "Country list cannot contain 0s before the last non-0 element")]
fn test_country_list_sorting_fail_with_0_in_middle() {
    let country_list: [u32; 6] = [4608577, 0, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test(should_fail_with = "Country list cannot start with 0")]
fn test_country_list_sorting_fail_when_starts_with_0() {
    let country_list: [u32; 6] = [0, 4608577, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test]
fn test_exclusion_check_pass() {
    let country_list: [u32; 6] = [4608577, 4608582, 4608590, 0, 0, 0];
    check_exclusion(4608576, country_list);
    check_exclusion(4608580, country_list);
    check_exclusion(4608589, country_list);
    check_exclusion(4608591, country_list);
}

#[test(should_fail)]
fn test_exclusion_check_fail() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608577, country_list);
}

#[test(should_fail)]
fn test_exclusion_check_fail_2() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608578, country_list);
}
