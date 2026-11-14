// Base proof of an Aadhaar Secure QR code, in place of the three chip base proofs. Outputs the
// same comm_out as the integrity check circuit. Public: certificate_registry_root, comm_out,
// credential_scheme.

use aadhaar::{
    AADHAAR_DELIMITER_COUNT, AADHAAR_MAX_DATA_LENGTH, CERTIFICATE_TREE_HEIGHT,
    commit_to_disclosure_aadhaar, parse_aadhaar_data, verify_uidai_key_in_registry,
};
use sig_check_rsa::verify_signature;
use utils::constants::CREDENTIAL_SCHEME_UIDAI_AADHAAR;

fn main(
    certificate_registry_root: pub Field,
    schema_version: u16,
    timestamp: u32,
    certificate_tree_index: Field,
    certificate_tree_hash_path: [Field; CERTIFICATE_TREE_HEIGHT],
    certificate_tags: [Field; 3],
    uidai_cert_expiry: u32,
    uidai_cert_fingerprint: Field,
    revocation_tree_root: Field,
    masterlist_tree_root: Field,
    // Decompressed QR data less its trailing 256-byte signature, zero-padded
    qr_data: [u8; AADHAAR_MAX_DATA_LENGTH],
    qr_data_length: u32,
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
    signature: [u8; 256],
    pubkey: [u8; 256],
    pubkey_redc_param: [u8; 257],
    dg1_salt: Field,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
) -> pub (Field, Field) {
    let aadhaar = parse_aadhaar_data(qr_data, qr_data_length, delimiter_indices);
    assert(
        aadhaar.signed_on <= uidai_cert_expiry as u64,
        "The UIDAI certificate had expired when the QR code was signed",
    );
    verify_uidai_key_in_registry(
        pubkey,
        certificate_registry_root,
        schema_version,
        timestamp,
        certificate_tree_index,
        certificate_tree_hash_path,
        certificate_tags,
        uidai_cert_expiry,
        uidai_cert_fingerprint,
        revocation_tree_root,
        masterlist_tree_root,
    );
    assert(
        verify_signature::<256, 0, AADHAAR_MAX_DATA_LENGTH, 32>(
            pubkey,
            signature,
            pubkey_redc_param,
            65537,
            qr_data,
            qr_data_length,
            0,
        ),
        "Failed to verify the UIDAI signature",
    );

    let (comm_out, _private_nullifier) = commit_to_disclosure_aadhaar(
        aadhaar,
        dg1_salt,
        expiry_date_salt,
        dg2_hash_salt,
        private_nullifier_salt,
    );

    (comm_out, CREDENTIAL_SCHEME_UIDAI_AADHAAR)
}
