// This is an auto-generated file, to change the code please edit ./src/ts/lib/circuit-builder.ts
use sig_check_rsa::verify_signature;
use commitment::commit_to_dsc;

fn main(
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    salt: Field,
    country: str<3>,
    tbs_certificate: [u8; 700],
    tbs_certificate_len: u64,
    csc_pubkey: [u8; 384],
    csc_pubkey_redc_param: [u8; 385],
    dsc_signature: [u8; 384],
    exponent: u32,
) -> pub Field {
    assert(verify_signature::<384, 0, 700>(
        csc_pubkey,
        dsc_signature,
        csc_pubkey_redc_param,
        exponent,
        tbs_certificate,
        tbs_certificate_len,
    ));
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_registry_id,
        country,
        tbs_certificate,
        salt,
        csc_pubkey,
    );
    comm_out
}
