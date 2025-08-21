use sha1::sha1;
use sha256;
use sha512::{sha384, sha512};
use utils::check_zero_padding;

pub fn sha1_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u64,
) -> [u8; 20] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len as u32);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len as u32);
    sha1::sha1_var(data_to_sign_vec)
}

pub fn sha256_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u64,
) -> [u8; 32] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len as u32);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha256::sha256_var(data_to_sign, data_to_sign_len)
}

pub fn sha384_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u64,
) -> [u8; 48] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len as u32);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len as u32);
    sha384::sha384_var(data_to_sign_vec)
}

pub fn sha512_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u64,
) -> [u8; 64] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len as u32);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len as u32);
    sha512::sha512_var(data_to_sign_vec)
}
