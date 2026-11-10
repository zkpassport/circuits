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
# Outputs
############################################################
# comm_out -> commitment over the salted DG1, expiry date, photo hash and private nullifier
# param_commitment -> commitment over the UIDAI public key, checked outside the circuit
#                     against UIDAI's published keys
# credential_scheme -> CREDENTIAL_SCHEME_UIDAI_AADHAAR
*/

use aadhaar::{
    AADHAAR_DELIMITER_COUNT, AADHAAR_MAX_DATA_LENGTH, calculate_aadhaar_param_commitment,
    commit_to_disclosure_aadhaar, parse_aadhaar_data,
};
use sig_check_rsa::verify_signature;
use utils::constants::CREDENTIAL_SCHEME_UIDAI_AADHAAR;

fn main(
    // The decompressed QR data without its last 256 bytes (the signature), zero-padded
    qr_data: [u8; AADHAAR_MAX_DATA_LENGTH],
    qr_data_length: u32,
    // Indices of the delimiters before the photo; V1 data uses the first 16
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
    signature: [u8; 256],
    // @committed
    // The UIDAI public key is committed to (via parameter commitment) and verified outside the circuit
    pubkey: [u8; 256],
    pubkey_redc_param: [u8; 257],
    dg1_salt: Field,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
) -> pub (Field, Field, Field) {
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

    (comm_out, calculate_aadhaar_param_commitment(pubkey), CREDENTIAL_SCHEME_UIDAI_AADHAAR)
}
