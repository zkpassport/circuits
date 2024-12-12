use sig_check_ecdsa::verify_signature;
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;

fn main(
    comm_in: pub Field,
    salt: Field,
    dg1: [u8; 95],
    dsc_pubkey_x: [u8; 32],
    dsc_pubkey_y: [u8; 32],
    sod_signature: [u8; 64],
    tbs_certificate: [u8; 1500],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
) -> pub Field {
    verify_ecdsa_pubkey_in_tbs(
        dsc_pubkey_x,
        dsc_pubkey_y,
        tbs_certificate,
        pubkey_offset_in_tbs,
    );
    assert(verify_signature(
        dsc_pubkey_x,
        dsc_pubkey_y,
        sod_signature,
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
