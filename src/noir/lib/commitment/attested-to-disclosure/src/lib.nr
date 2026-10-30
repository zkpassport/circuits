use common::{hash_salt_dg1_dg2_hash_private_nullifier, normalize_dg2_hash};
use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::DG1_LENGTH,
    get_dob_from_mrz,
    get_document_number_from_mrz,
    get_expiry_date_from_mrz,
    get_issuing_country_from_mrz,
    pack_be_bytes_into_fields,
    types::{DG1Data, SaltedValue},
};

pub mod tests;

/*
# Attested ID to Disclosure
# The base of a Tier 2 proof: an ID read by camera, with no chip to sign its data.
# The device attests, through App Attest, the DG1 it read together with the portrait it
# matched against a live face. This library turns that attestation into the same commitment
# the chip base proofs produce, so every disclosure circuit works on it unchanged.
*/

/// Domain separator for the Tier 2 private nullifier, so it can never collide with a chip one
pub global TIER2_NULLIFIER_DOMAIN: Field = 0x5449455232; // "TIER2"

/// The attested digest covers the DG1 and the portrait hash, both as the device read them
pub global ATTESTED_DIGEST_INPUT_LENGTH: u32 = DG1_LENGTH + 32;

/// The length of the fields the Tier 2 nullifier is derived from
global NULLIFIER_FIELDS_LENGTH: u32 = 3 + 9 + 6;

/// The digest the device attests for a camera-read ID: SHA-256 over the padded DG1 followed
/// by the SHA-256 of the portrait. It sits in the attestation where a chip ID's DG2 hash does.
pub fn calculate_attested_digest(dg1: DG1Data, portrait_hash: [u8; 32]) -> [u8; 32] {
    let mut input: [u8; ATTESTED_DIGEST_INPUT_LENGTH] = [0; ATTESTED_DIGEST_INPUT_LENGTH];
    for i in 0..DG1_LENGTH {
        input[i] = dg1[i];
    }
    for i in 0..32 {
        input[DG1_LENGTH + i] = portrait_hash[i];
    }
    sha256::sha256_var(input, ATTESTED_DIGEST_INPUT_LENGTH)
}

/// A camera-read ID has no signature to derive a nullifier from, so it comes from the MRZ
/// fields that carry a check digit: issuing country, document number and date of birth.
/// Names have no check digit and OCR may read them differently each time, so they are left out.
pub fn calculate_tier2_private_nullifier(dg1: DG1Data) -> Field {
    let issuing_country = get_issuing_country_from_mrz(dg1);
    let document_number = get_document_number_from_mrz(dg1);
    let date_of_birth = get_dob_from_mrz(dg1);

    let mut fields: [u8; NULLIFIER_FIELDS_LENGTH] = [0; NULLIFIER_FIELDS_LENGTH];
    for i in 0..3 {
        fields[i] = issuing_country[i];
    }
    for i in 0..9 {
        fields[3 + i] = document_number[i];
    }
    for i in 0..6 {
        fields[12 + i] = date_of_birth[i];
    }
    let packed: [Field; 1] = pack_be_bytes_into_fields::<NULLIFIER_FIELDS_LENGTH, 1, 31>(fields);
    Poseidon2::hash([TIER2_NULLIFIER_DOMAIN, packed[0]], 2)
}

/// The commitment the disclosure circuits take as `comm_in`, with the same shape as the one
/// from the integrity check circuit of a chip ID. Returns it with the private nullifier.
pub fn commit_to_disclosure_attested(
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    salted_dg2_hash_type: SaltedValue<u32>,
    private_nullifier_salt: Field,
    attested_digest: [u8; 32],
) -> (Field, Field) {
    let private_nullifier = calculate_tier2_private_nullifier(salted_dg1.value);
    let salted_expiry_date =
        SaltedValue::from_value(expiry_date_salt, get_expiry_date_from_mrz(salted_dg1.value));
    let comm_out = hash_salt_dg1_dg2_hash_private_nullifier(
        salted_dg1,
        salted_expiry_date,
        SaltedValue::from_value(dg2_hash_salt, normalize_dg2_hash(attested_digest)),
        salted_dg2_hash_type,
        SaltedValue::from_value(private_nullifier_salt, private_nullifier),
    );
    (comm_out, private_nullifier)
}
