use std::hash::sha256;
use std::ecdsa_secp256r1;

pub fn verify_signature<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash)
}
