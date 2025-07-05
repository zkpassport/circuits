use bigcurve::curves::brainpoolP256r1::{BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};
use bigcurve::curves::brainpoolP256t1::{BrainpoolP256t1_Fq, BrainpoolP256t1_Fr};
use bigcurve::curves::brainpoolP384r1::{BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};
use bigcurve::curves::brainpoolP384t1::{BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};
use bigcurve::curves::brainpoolP512r1::{BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};
use bigcurve::curves::brainpoolP512t1::{BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};
use bignum::bignum::BigNum;
use ecdsa::ecdsa::{
    verify_brainpoolp256r1_ecdsa, verify_brainpoolp256t1_ecdsa, verify_brainpoolp384r1_ecdsa,
    verify_brainpoolp384t1_ecdsa, verify_brainpoolp512r1_ecdsa, verify_brainpoolp512t1_ecdsa,
    verify_secp256r1_ecdsa, verify_secp384r1_ecdsa, verify_secp521r1_ecdsa,
};
use std::ecdsa_secp256r1;
use utils::concat_array;

pub fn verify_nist_p256_blackbox<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let signature = concat_array(signature_r, signature_s);
    ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash)
}

pub fn verify_nist_p256<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp256r1_Fq = Secp256r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: Secp256r1_Fr = Secp256r1_Fr::from_be_bytes(signature_s);
    verify_secp256r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_nist_p384<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(signature_s);
    verify_secp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_nist_p521<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 66],
    pubkey_y: [u8; 66],
    signature_r: [u8; 66],
    signature_s: [u8; 66],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: Secp521r1_Fq = Secp521r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: Secp521r1_Fr = Secp521r1_Fr::from_be_bytes(signature_s);
    verify_secp521r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_256r1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256r1_Fq = BrainpoolP256r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp256r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_256t1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP256t1_Fq = BrainpoolP256t1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP256t1_Fq = BrainpoolP256t1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP256t1_Fr = BrainpoolP256t1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP256t1_Fr = BrainpoolP256t1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp256t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_384r1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384r1_Fq = BrainpoolP384r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp384r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_384t1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    signature_r: [u8; 48],
    signature_s: [u8; 48],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP384t1_Fq = BrainpoolP384t1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP384t1_Fq = BrainpoolP384t1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP384t1_Fr = BrainpoolP384t1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP384t1_Fr = BrainpoolP384t1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp384t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_512r1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512r1_Fq = BrainpoolP512r1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp512r1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}

pub fn verify_brainpool_512t1<let HASH_BYTE_SIZE: u32>(
    pubkey_x: [u8; 64],
    pubkey_y: [u8; 64],
    signature_r: [u8; 64],
    signature_s: [u8; 64],
    msg_hash: [u8; HASH_BYTE_SIZE],
) -> bool {
    let pubkey_x_bignum: BrainpoolP512t1_Fq = BrainpoolP512t1_Fq::from_be_bytes(pubkey_x);
    let pubkey_y_bignum: BrainpoolP512t1_Fq = BrainpoolP512t1_Fq::from_be_bytes(pubkey_y);
    let signature_r_bignum: BrainpoolP512t1_Fr = BrainpoolP512t1_Fr::from_be_bytes(signature_r);
    let signature_s_bignum: BrainpoolP512t1_Fr = BrainpoolP512t1_Fr::from_be_bytes(signature_s);
    verify_brainpoolp512t1_ecdsa(
        pubkey_x_bignum,
        pubkey_y_bignum,
        msg_hash,
        (signature_r_bignum, signature_s_bignum),
    )
}
