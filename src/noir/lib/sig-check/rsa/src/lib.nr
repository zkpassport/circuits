use bignum::{params::BigNumParams, RuntimeBigNum};
use common::sha256_and_check_data_to_sign;
use rsa::rsa::{verify_sha256_pkcs1v15, verify_sha256_pss};

pub fn verify_signature<let SIG_BYTES: u32, let IS_PSS: u32, let DATA_TO_SIGN_LEN: u32>(
    pubkey_bytes: [u8; SIG_BYTES],
    sig_bytes: [u8; SIG_BYTES],
    redc_param_bytes: [u8; SIG_BYTES + 1],
    exponent: u32,
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    assert(
        (SIG_BYTES == 512) | (SIG_BYTES == 384) | (SIG_BYTES == 256) | (SIG_BYTES == 128),
        "Only modulus of bit size 1024, 2048, 3072 and 4096 are supported",
    );
    let msg_hash = sha256_and_check_data_to_sign(data_to_sign, data_to_sign_len);

    let pubkey = utils::from_byte_be_to_fields::<SIG_BYTES, (SIG_BYTES + 14) / 15>(pubkey_bytes);
    let redc_param = utils::from_byte_be_to_fields::<SIG_BYTES + 1, _>(redc_param_bytes);
    let params = BigNumParams::new(false, pubkey, redc_param);

    let signature = RuntimeBigNum::from_be_bytes(params, sig_bytes);

    if (IS_PSS == 1) {
        verify_sha256_pss::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
    } else {
        verify_sha256_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
    }
}
