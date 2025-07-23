// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_signature;

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    dsc_pubkey: [u8; 512],
    dsc_pubkey_redc_param: [u8; 513],
    sod_signature: [u8; 512],
    tbs_certificate: [u8; 700],
    pubkey_offset_in_tbs: u32,
    signed_attributes: [u8; 220],
    signed_attributes_size: u64,
    exponent: u32,
    e_content: [u8; 700],
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate, pubkey_offset_in_tbs);
    assert(
        verify_signature::<512, 1, 200, 48>(
            dsc_pubkey,
            sod_signature,
            dsc_pubkey_redc_param,
            exponent,
            signed_attributes,
            signed_attributes_size,
        ),
        "RSA signature verification failed",
    );
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
