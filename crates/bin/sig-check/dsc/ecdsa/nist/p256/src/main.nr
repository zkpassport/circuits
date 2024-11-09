use sig_check_ecdsa::verify_signature;
//use commitment::commit_to_dsc;

/*fn concat_csc_pubkey(csc_pubkey_x: [u8; 32], csc_pubkey_y: [u8; 32]) -> [u8; 64] {
    let mut csc_pubkey = [0 as u8; 64];
    for i in 0..32 {
        csc_pubkey[i] = csc_pubkey_x[i];
        csc_pubkey[i + 32] = csc_pubkey_y[i];
    }
    csc_pubkey
}*/

//#[recursive]
fn main(
    /*certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    salt: Field,
    country: str<3>,*/
    csc_pubkey_x: [u8; 32],
    csc_pubkey_y: [u8; 32],
    dsc_signature: [u8; 64],
    tbs_certificate: [u8; 1024],
    tbs_certificate_len: u64,
) /*-> pub Field*/
{
    assert(verify_signature(
        csc_pubkey_x,
        csc_pubkey_y,
        dsc_signature,
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
        concat_csc_pubkey(csc_pubkey_x, csc_pubkey_y),
    );
    comm_out*/
}
