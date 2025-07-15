// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_ecdsa::verify_brainpool_256r1;
use utils::split_array;
use sig_check_common::sha256_and_check_data_to_sign;

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    dsc_pubkey_x: [u8; 32],
    dsc_pubkey_y: [u8; 32],
    sod_signature: [u8; 64],
    tbs_certificate: [u8; 1200],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
    e_content: [u8; 700],
) -> pub Field {
    let (r, s) = split_array(sod_signature);
    let msg_hash = sha256_and_check_data_to_sign(signed_attributes, signed_attributes_size);
    verify_ecdsa_pubkey_in_tbs(
        dsc_pubkey_x,
        dsc_pubkey_y,
        tbs_certificate,
        pubkey_offset_in_tbs,
    );
    assert(verify_brainpool_256r1(
        dsc_pubkey_x,
        dsc_pubkey_y,
        r,
        s,
        msg_hash,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
    );
    comm_out
}
