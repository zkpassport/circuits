use bigcurve::curves::secp384r1::{Secp384r1_Params, Secp384r1Fq, Secp384r1Fr};
use bignum::bignum::BigNum;
use ecdsa::brainpoolP256r1::params::{BrainpoolP256r1Fq, BrainpoolP256r1Fr};
use ecdsa::brainpoolP256t1::params::{BrainpoolP256t1Fq, BrainpoolP256t1Fr};
use ecdsa::brainpoolP384r1::params::{BrainpoolP384r1Fq, BrainpoolP384r1Fr};
use ecdsa::brainpoolP384t1::params::{BrainpoolP384t1Fq, BrainpoolP384t1Fr};
use ecdsa::brainpoolP512r1::params::{BrainpoolP512r1Fq, BrainpoolP512r1Fr};
use ecdsa::brainpoolP512t1::params::{BrainpoolP512t1Fq, BrainpoolP512t1Fr};
use ecdsa::ecdsa::{
    verify_brainpoolp256r1_ecdsa, verify_brainpoolp256t1_ecdsa, verify_brainpoolp384r1_ecdsa,
    verify_brainpoolp384t1_ecdsa, verify_brainpoolp512r1_ecdsa, verify_brainpoolp512t1_ecdsa,
    verify_secp384r1_ecdsa, verify_secp521r1_ecdsa,
};
use ecdsa::secp521r1::params::{Secp521r1Fq, Secp521r1Fr};
use std::hash::sha256;
use utils::check_bytes_zero_padding;
use utils::{
    ECDSA_CURVE_BRAINPOOL_B256R1, ECDSA_CURVE_BRAINPOOL_B256T1, ECDSA_CURVE_BRAINPOOL_B384R1,
    ECDSA_CURVE_BRAINPOOL_B384T1, ECDSA_CURVE_BRAINPOOL_B512R1, ECDSA_CURVE_BRAINPOOL_B512T1,
    ECDSA_CURVE_P384, ECDSA_CURVE_P521,
};

pub fn verify_p384<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_s);
    verify_secp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_p521<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 66],
    pubkey_y: [u8; 66],
    signature_r: [u8; 66],
    signature_s: [u8; 66],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_s);
    verify_secp521r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p256r1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp256r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p256t1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp256t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p384r1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p384t1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp384t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p512r1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp512r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_p512t1<let DATA_TO_SIGN_LEN: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    let pubkey_x_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_s);
    verify_brainpoolp512t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

// Doesn't compile
/**
Arithmetic generics simplification failed: `((8: numeric u32) - (((NBytes : u32)'53600 -> (66: numeric u32) * (8: numeric u32)) - (MOD_BITS : u32)'53599 -> (384: numeric u32)))` != `((8: numeric u32) - (((NBytes : u32)'53600 -> (66: numeric u32) * (8: numeric u32)) - (MOD_BITS : u32)'53599 -> (384: numeric u32)))`
 most_significant_byte.assert_max_bit_size::<8 - (NBytes * 8 - MOD_BITS)>();
*/
pub fn verify_signature<let DATA_TO_SIGN_LEN: u32, let CURVE: u32, let PUBKEY_BYTE_LEN: u32>(
    pubkey_x: [u8; PUBKEY_BYTE_LEN],
    pubkey_y: [u8; PUBKEY_BYTE_LEN],
    signature_r: [u8; PUBKEY_BYTE_LEN],
    signature_s: [u8; PUBKEY_BYTE_LEN],
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> bool {
    // Check that the data signed does stop at the specified length
    // to prevent the prover from using the bytes beyond that point
    // to manipulate it in their favor
    check_bytes_zero_padding(data_to_sign, data_to_sign_len as u32);

    let msg_hash = sha256::sha256_var(data_to_sign, data_to_sign_len);
    if CURVE == ECDSA_CURVE_P384 {
        let pubkey_x_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: Secp384r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: Secp384r1Fr = BigNum::from_be_bytes(signature_s);
        verify_secp384r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_P521 {
        let pubkey_x_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: Secp521r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: Secp521r1Fr = BigNum::from_be_bytes(signature_s);
        verify_secp521r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B256R1 {
        let pubkey_x_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP256r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP256r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp256r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B384R1 {
        let pubkey_x_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP384r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP384r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp384r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B512R1 {
        let pubkey_x_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP512r1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP512r1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp512r1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B256T1 {
        let pubkey_x_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP256t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP256t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp256t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B384T1 {
        let pubkey_x_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP384t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP384t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp384t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else if CURVE == ECDSA_CURVE_BRAINPOOL_B512T1 {
        let pubkey_x_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_x);
        let pubkey_y_bignum: BrainpoolP512t1Fq = BigNum::from_be_bytes(pubkey_y);
        let signature_r_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_r);
        let signature_s_bignum: BrainpoolP512t1Fr = BigNum::from_be_bytes(signature_s);
        verify_brainpoolp512t1_ecdsa(
            pubkey_x_bignum,
            pubkey_y_bignum,
            msg_hash,
            (signature_r_bignum, signature_s_bignum),
        )
    } else {
        false
    }
}
