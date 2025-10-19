// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_rsa::verify_signature;
use utils::types::Alpha3CountryCode;

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; 1200],
    csc_pubkey: [u8; 256],
    csc_pubkey_redc_param: [u8; 257],
    dsc_signature: [u8; 256],
    exponent: u32,
) -> pub Field {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len = unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    assert(
        verify_signature::<256, 1, 1200, 20>(
            csc_pubkey,
            dsc_signature,
            csc_pubkey_redc_param,
            exponent,
            tbs_certificate,
            tbs_certificate_len,
        ),
        "RSA signature verification failed",
    );
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        csc_pubkey,
    );
    comm_out
}
