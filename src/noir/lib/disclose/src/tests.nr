use super::{calculate_param_commitment, get_disclosed_bytes};
use utils::constants::{MAX_MRZ_LENGTH, SAMPLE_DG1};
use utils::get_mrz_from_dg1;

#[test]
fn test_get_disclosed_bytes() {
    let mask = [1 as u1; MAX_MRZ_LENGTH];
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, mask);
    assert_eq(disclosed_bytes, get_mrz_from_dg1(SAMPLE_DG1));
}

#[test]
fn test_get_disclosed_bytes_zero() {
    let mask = [0 as u1; MAX_MRZ_LENGTH];
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, mask);
    assert_eq(disclosed_bytes, [0 as u8; MAX_MRZ_LENGTH]);
}

#[test]
fn test_get_disclosed_bytes_partial() {
    let mut mask = [0 as u1; MAX_MRZ_LENGTH];
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

#[test]
fn test_calculate_param_commitment() {
    let disclose_mask = [1 as u1; MAX_MRZ_LENGTH];
    let disclosed_bytes = get_disclosed_bytes(SAMPLE_DG1, disclose_mask);
    let commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    assert_eq(commitment, 0x10e0ee79b56de1ef2bad643678d973fe883d9d022be50e6f0627b57a66241e16);
}
