// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_common::sha512_and_check_data_to_sign;
use sig_check_ecdsa::verify_nist_p256;
use utils::{concat_array, split_array};

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: Field,
    salt: Field,
    country: str<3>,
    csc_pubkey_x: [u8; 32],
    csc_pubkey_y: [u8; 32],
    dsc_signature: [u8; 64],
    tbs_certificate: [u8; 1600],
    tbs_certificate_len: u64,
) -> pub Field {
    let (r, s) = split_array(dsc_signature);
    let msg_hash = sha512_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(
        verify_nist_p256(csc_pubkey_x, csc_pubkey_y, r, s, msg_hash),
        "ECDSA signature verification failed",
    );
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        5,
        concat_array(csc_pubkey_x, csc_pubkey_y),
    );
    comm_out
}
