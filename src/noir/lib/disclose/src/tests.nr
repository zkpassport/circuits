use super::get_disclosed_bytes;
use utils::constants::SAMPLE_DG1;
use utils::get_mrz_from_dg1;

#[test]
fn test_get_disclosed_bytes() {
    let mask = [1 as u1; 90];
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, mask);
    assert_eq(disclosed_bytes, get_mrz_from_dg1(SAMPLE_DG1));
}

#[test]
fn test_get_disclosed_bytes_zero() {
    let mask = [0 as u1; 90];
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, mask);
    assert_eq(disclosed_bytes, [0 as u8; 90]);
}

#[test]
fn test_get_disclosed_bytes_partial() {
    let mut mask = [0 as u1; 90];
    for i in 0..45 {
        mask[i] = 1;
    }
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, mask);
    let full_mrz = get_mrz_from_dg1(SAMPLE_DG1);
    for i in 0..45 {
        assert_eq(disclosed_bytes[i], full_mrz[i]);
    }
    for i in 45..90 {
        assert_eq(disclosed_bytes[i], 0);
    }
}
