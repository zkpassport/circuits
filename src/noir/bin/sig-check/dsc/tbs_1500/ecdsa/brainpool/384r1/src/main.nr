// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_ecdsa::verify_brainpool_384r1;
use utils::{concat_array, split_array};

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    salt: Field,
    country: str<3>,
    csc_pubkey_x: [u8; 48],
    csc_pubkey_y: [u8; 48],
    dsc_signature: [u8; 96],
    tbs_certificate: [u8; 1500],
    tbs_certificate_len: u64,
) -> pub Field {
    let (r, s) = split_array(dsc_signature);
    assert(verify_brainpool_384r1(
        csc_pubkey_x,
        csc_pubkey_y,
        r,
        s,
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
        concat_array(csc_pubkey_x, csc_pubkey_y),
    );
    comm_out
}