use sig_check_rsa::verify_signature;
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;

fn main(
    comm_in: pub Field,
    salt: Field,
    dg1: [u8; 95],
    tbs_certificate: [u8; 1500],
    dsc_pubkey: [u8; 512],
    dsc_pubkey_redc_param: [u8; 513],
    sod_signature: [u8; 512],
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
    exponent: u32,
    pubkey_offset_in_tbs: u32,
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate, pubkey_offset_in_tbs);
    assert(verify_signature::<512, 1, 200>(
        dsc_pubkey,
        sod_signature,
        dsc_pubkey_redc_param,
        exponent,
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
