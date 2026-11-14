/*
############################################################
# Aadhaar ID
############################################################
# The base proof of an Aadhaar verification, in place of the three chip base proofs. It
# verifies UIDAI's signature over the Secure QR data, converts the name, date of birth,
# gender and the last 4 digits of the Aadhaar number into a passport-shaped DG1 with an
# expiry date 10 years after the QR was signed, and commits to the SHA-256 of the photo in
# the DG2 hash slot.
#
# It outputs the same commitment as the integrity check circuit, so the disclosure circuits
# and the facematch circuit take it as `comm_in` unchanged.
#
# The UIDAI key must be a UIDAI leaf of the Certificate Registry, as a CSCA must be for a
# chip ID, so the verifier checks `certificate_registry_root` like a DSC proof's.
#
# Public inputs and outputs
############################################################
# certificate_registry_root -> the Certificate Registry root the UIDAI key is under
# comm_out -> commitment over the salted DG1, expiry date, photo hash and private nullifier
# credential_scheme -> CREDENTIAL_SCHEME_UIDAI_AADHAAR
*/

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
    // The decompressed QR data without its last 256 bytes (the signature), zero-padded
    qr_data: [u8; AADHAAR_MAX_DATA_LENGTH],
    qr_data_length: u32,
    // Indices of the delimiters before the photo; V1 data uses the first 16
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
    signature: [u8; 256],
    pubkey: [u8; 256],
    pubkey_redc_param: [u8; 257],
    dg1_salt: Field,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
) -> pub (Field, Field) {
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

    let aadhaar = parse_aadhaar_data(qr_data, qr_data_length, delimiter_indices);
    let (comm_out, _private_nullifier) = commit_to_disclosure_aadhaar(
        aadhaar,
        dg1_salt,
        expiry_date_salt,
        dg2_hash_salt,
        private_nullifier_salt,
    );

    (comm_out, CREDENTIAL_SCHEME_UIDAI_AADHAAR)
}
