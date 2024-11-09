use sig_check_rsa::verify_signature;
//use commitment::commit_to_dsc;

//#[recursive]
fn main(
    /*certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    salt: Field,
    country: str<3>,*/
    tbs_certificate: [u8; 1024],
    tbs_certificate_len: u64,
    csc_pubkey: [u8; 256],
    csc_pubkey_redc_param: [u8; 257],
    dsc_signature: [u8; 256],
    exponent: u32,
) /*-> pub Field*/
{
    assert(verify_signature::<256, 1, 1024>(
        csc_pubkey,
        dsc_signature,
        csc_pubkey_redc_param,
        exponent,
        tbs_certificate,
        tbs_certificate_len,
    ));
    /*let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_registry_id,
        country,
        tbs_certificate,
        salt,
        csc_pubkey,
    );
    comm_out*/
}
