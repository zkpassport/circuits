use super::{
    check_country_list_sorted, check_exclusion, constrain_last_index, get_last_index,
    unsafe_get_closest_index,
};

#[test]
fn test_get_closest_index_before_first_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, 4608576) };
    assert_eq(closest_index_from_above, 0);
}

#[test]
fn test_get_closest_index_after_last_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, 4608583) };
    assert_eq(closest_index_from_above, -1);
}

#[test]
fn test_get_closest_index_in_middle() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, 4608580) };
    // Should get the index of the item after it, since it's the closest index from above
    assert_eq(closest_index_from_above, 4);
}

#[test]
fn test_get_closest_index_last_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let closest_index_from_above = unsafe { unsafe_get_closest_index(country_list, 4608582) };
    // Should get -1 since there's no item after it
    assert_eq(closest_index_from_above, -1);
}

#[test]
fn test_get_last_index_with_0s() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 0, 0];
    let last_index = get_last_index(country_list);
    // Should get the index of the last item before the 0s
    assert_eq(last_index, 3);
}

#[test]
fn test_get_last_index_without_0s() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let last_index = get_last_index(country_list);
    // Should get the index of the last item
    assert_eq(last_index, 5);
}

#[test]
fn test_get_last_index_empty() {
    let country_list: [u32; 6] = [0, 0, 0, 0, 0, 0];
    let last_index = get_last_index(country_list);
    // Should get -1 since the list is empty
    assert_eq(last_index, -1);
}

#[test]
fn test_constrain_last_index() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let last_index = 5;
    constrain_last_index(country_list, last_index);
}

#[test(should_fail_with = "The list is not padded with 0s after the last nonzero element")]
fn test_constrain_last_index_fail() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let last_index = 3;
    constrain_last_index(country_list, last_index);
}

#[test(should_fail_with = "The item at the last index must be nonzero")]
fn test_constrain_last_index_last_index_non_zero() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 0];
    let last_index = 5;
    constrain_last_index(country_list, last_index);
}

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

#[test]
fn test_country_list_sorting_check_full_lists() {
    // List in descending order, so not sorted in ascending order
    let country_list: [u32; 6] = [4608578, 4608577, 4608576, 4608575, 4608574, 4608573];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List in ascending order
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, true);

    // List with duplicates
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608579, 4608580, 4608581];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);

    // List not in a particular order
    let country_list: [u32; 6] = [4608577, 4608579, 4608578, 4608480, 4638581, 4708582];
    let is_sorted = check_country_list_sorted(country_list);
    assert_eq(is_sorted, false);
}

#[test(should_fail_with = "Country list cannot contain 0s before the last non-0 element")]
fn test_country_list_sorting_fail_with_0_in_middle() {
    let country_list: [u32; 6] = [4608577, 0, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test(should_fail_with = "Country list cannot contain 0s before the last non-0 element")]
fn test_country_list_sorting_fail_with_0_in_middle_full_list() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 4608580, 4608581];
    check_country_list_sorted(country_list);
}

#[test(should_fail_with = "Country list cannot start with 0")]
fn test_country_list_sorting_fail_when_starts_with_0() {
    let country_list: [u32; 6] = [0, 4608577, 4608578, 4608579, 0, 0];
    check_country_list_sorted(country_list);
}

#[test(should_fail_with = "Country list cannot start with 0")]
fn test_country_list_sorting_fail_when_starts_with_0_full_list() {
    let country_list: [u32; 6] = [0, 4608577, 4608578, 4608579, 4608580, 4608581];
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

#[test]
fn test_exclusion_check_pass_full_list() {
    let country_list: [u32; 6] = [4608577, 4608582, 4608590, 4608591, 4608592, 4608595];
    check_exclusion(4608576, country_list);
    check_exclusion(4608580, country_list);
    check_exclusion(4608589, country_list);
    check_exclusion(4608594, country_list);
    check_exclusion(4608596, country_list);
}

#[test(should_fail_with = "The country is in the list (not greater than the expected lower bound)")]
fn test_exclusion_check_fail_first_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608577, country_list);
}

#[test(should_fail_with = "The country is in the list (not greater than the last item)")]
fn test_exclusion_check_fail_last_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    check_exclusion(4608582, country_list);
}

#[test(should_fail_with = "The country is in the list (not greater than the expected lower bound)")]
fn test_exclusion_check_fail_middle_item() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 0, 0, 0];
    check_exclusion(4608578, country_list);
}

#[test(should_fail_with = "The country is in the list (not greater than the expected lower bound)")]
fn test_exclusion_check_fail_middle_item_full_list() {
    let country_list: [u32; 6] = [4608577, 4608578, 4608579, 4608580, 4608581, 4608582];
    check_exclusion(4608580, country_list);
}
