use common::{hash_salt_dg1_dg2_hash_private_nullifier, normalize_dg2_hash};
use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{ASCII_CODE_FOR_LESS_THAN, DG1_LENGTH, DG1_TO_MRZ_OFFSET},
    get_dob_from_mrz,
    get_document_number_from_mrz,
    get_expiry_date_from_mrz,
    get_issuing_country_from_mrz,
    is_id_card,
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

/// The attested digest covers the DG1 and the portrait hash, both as the device read them
pub global ATTESTED_DIGEST_INPUT_LENGTH: u32 = DG1_LENGTH + 32;

/// The document number as the nullifier takes it: up to 24 characters
global NULLIFIER_DOCUMENT_NUMBER_LENGTH: u32 = 24;

/// Prefixed to the Tier 2 nullifier's fields, so no table built for another system hashing the
/// same document fields applies to it, and its nullifiers never coincide with another scheme's
global NULLIFIER_DOMAIN: [u8; 11] = "ATTESTED_ID".as_bytes();
global NULLIFIER_DOMAIN_LENGTH: u32 = 11;

/// The length of the fields the Tier 2 nullifier is derived from: 50 bytes, two packed fields
global NULLIFIER_FIELDS_LENGTH: u32 =
    NULLIFIER_DOMAIN_LENGTH + 3 + NULLIFIER_DOCUMENT_NUMBER_LENGTH + 6 + 6;

/// Where a TD1 MRZ's optional data starts, after the document number and its check digit
global TD1_OPTIONAL_DATA_INDEX: u32 = 15;

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

/// The whole document number. A TD1 number longer than 9 characters leaves its check digit
/// position empty and continues in the optional data (ICAO 9303-5), which is then taken as well;
/// otherwise the rest is filler. Sub-national documents (US driving licences) put their
/// subdivision code first, since their numbers are unique only within it.
fn get_full_document_number(dg1: DG1Data) -> [u8; NULLIFIER_DOCUMENT_NUMBER_LENGTH] {
    let number = get_document_number_from_mrz(dg1);
    let mut full = [ASCII_CODE_FOR_LESS_THAN; NULLIFIER_DOCUMENT_NUMBER_LENGTH];
    for i in 0..9 {
        full[i] = number[i];
    }
    let mrz_start = DG1_TO_MRZ_OFFSET;
    if is_id_card(dg1) & (dg1[mrz_start + TD1_OPTIONAL_DATA_INDEX - 1] == ASCII_CODE_FOR_LESS_THAN) {
        for i in 0..(NULLIFIER_DOCUMENT_NUMBER_LENGTH - 9) {
            full[9 + i] = dg1[mrz_start + TD1_OPTIONAL_DATA_INDEX + i];
        }
    }
    full
}

/// A camera-read ID has no signature to derive a nullifier from, so it comes from the MRZ
/// fields every document has and OCR reads reliably: issuing country, and the whole document
/// number, date of birth and expiry date, which carry check digits, after the "ATTESTED_ID" domain. The same document always
/// gives the same nullifier; names are left out, as OCR may read them differently each time.
pub fn calculate_tier2_private_nullifier(dg1: DG1Data) -> Field {
    let issuing_country = get_issuing_country_from_mrz(dg1);
    let document_number = get_full_document_number(dg1);
    let date_of_birth = get_dob_from_mrz(dg1);
    let expiry_date = get_expiry_date_from_mrz(dg1);

    let mut fields: [u8; NULLIFIER_FIELDS_LENGTH] = [0; NULLIFIER_FIELDS_LENGTH];
    for i in 0..NULLIFIER_DOMAIN_LENGTH {
        fields[i] = NULLIFIER_DOMAIN[i];
    }
    let d = NULLIFIER_DOMAIN_LENGTH;
    for i in 0..3 {
        fields[d + i] = issuing_country[i];
    }
    for i in 0..NULLIFIER_DOCUMENT_NUMBER_LENGTH {
        fields[d + 3 + i] = document_number[i];
    }
    for i in 0..6 {
        fields[d + 3 + NULLIFIER_DOCUMENT_NUMBER_LENGTH + i] = date_of_birth[i];
        fields[d + 9 + NULLIFIER_DOCUMENT_NUMBER_LENGTH + i] = expiry_date[i];
    }
    let packed: [Field; 2] = pack_be_bytes_into_fields::<NULLIFIER_FIELDS_LENGTH, 2, 31>(fields);
    Poseidon2::hash(packed, 2)
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
