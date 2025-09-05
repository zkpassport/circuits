use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::check_zero_padding;

// File visually inspected.
// Technically missing tests to ensure the outputs are as expected,
// and to catch examples of badly-padded inputs.
pub fn sha1_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 20] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);

    // Consider using `::from_parts_unchecked`, since `::from_parts` is doing redundant work, 
    // given the above call to `check_zero_padding`.
    // Also `from_parts` mutates the contents of
    // the array which seems unnecessarily risky (even though that mutation won't bite in this case,
    // given the call to `check_zero_padding`).
    // Same comment for all other functions in this file that use BoundedVec.
    // (If you do choose to use `from_parts_unchecked`, please do add a comment to say that it's only safe to do so because of the `check_zero_padding` call, in case someone removes that call in future).

    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);
    sha1::sha1_var(data_to_sign_vec)
}

pub fn sha224_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 28] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);

    // Strange that some sha functions take a BoundedVec and others take a vanilla array.
    
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha224_var(data_to_sign, data_to_sign_len as u64)
}

pub fn sha256_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 32] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha256_var(data_to_sign, data_to_sign_len as u64)
}

pub fn sha384_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 48] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);
    sha384::sha384_var(data_to_sign_vec)
}

pub fn sha512_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 64] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);
    sha512::sha512_var(data_to_sign_vec)
}
