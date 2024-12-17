// This is an auto-generated file, to change the code please edit ./src/ts/lib/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_ecdsa::verify_brainpool_384t1;
use utils::split_array;

fn main(
    comm_in: pub Field,
    salt: Field,
    dg1: [u8; 95],
    dsc_pubkey_x: [u8; 48],
    dsc_pubkey_y: [u8; 48],
    sod_signature: [u8; 96],
    tbs_certificate: [u8; 1200],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
) -> pub Field {
    let (r, s) = split_array(sod_signature);
    verify_ecdsa_pubkey_in_tbs(
        dsc_pubkey_x,
        dsc_pubkey_y,
        tbs_certificate,
        pubkey_offset_in_tbs,
    );
    assert(verify_brainpool_384t1(
        dsc_pubkey_x,
        dsc_pubkey_y,
        r,
        s,
        signed_attributes,
        signed_attributes_size,
    ));
    let comm_out = commit_to_id(
        comm_in,
        salt,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
    );
    comm_out
}
