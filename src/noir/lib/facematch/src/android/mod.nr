use crate::constants::APP_ID_MAX_LEN;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sha256;
use sha512::sha384;
use sig_check_ecdsa::{verify_nist_p256, verify_nist_p384};
use utils::{
    check_zero_padding, find_subarray_index, get_array_slice, poseidon2_hash_packed,
    unsafe_get_asn1_element_length,
};

pub mod constants;
pub mod token;
use constants::{ANDROID_KEY_ORIGIN_GENERATED, OID_ANDROID_KEY_ATTESTATION};
//pub mod tests;

pub fn get_app_id_from_credential_tbs<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> ([u8; APP_ID_MAX_LEN], u32) {
    // Find Android Key Attestation extension OID in the TBS certificate
    let oid_offset = find_subarray_index(OID_ANDROID_KEY_ATTESTATION, tbs);
    assert(
        oid_offset < TBS_MAX_LEN,
        "Android Key Attestation OID not found in credential certificate",
    );

    // Look for the 6th item in the sequence (tagged with BF 85 45)
    // The 6th item contains the app ID as an OCTET STRING
    let APP_ID_SEARCH_DISTANCE = 200; // Search within 200 bytes after the OID

    let mut attestation_app_id_sequence_offset = TBS_MAX_LEN; // Default to not found
    let mut found_attestation_app_id_sequence = false;
    // Search for the attestation app id sequence tag pattern (BF 85 45) within the extension
    // attestationApplicationId [709] EXPLICIT OCTET STRING
    for i in 0..APP_ID_SEARCH_DISTANCE {
        if (oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 2 < TBS_MAX_LEN)
            & !found_attestation_app_id_sequence {
            if (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i] == 0xbf)
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 1] == 0x85)
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 2] == 0x45) {
                attestation_app_id_sequence_offset =
                    oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 4; // Skip the tag and length
                found_attestation_app_id_sequence = true;
            }
        }
    }
    assert(
        found_attestation_app_id_sequence,
        "Attestation app id sequence not found in app ID extension",
    );
    assert(
        attestation_app_id_sequence_offset < TBS_MAX_LEN,
        "Attestation app id sequence offset out of bounds",
    );

    // Look for OCTET STRING tag (0x04) and read the length dynamically
    let mut app_id_offset = TBS_MAX_LEN; // Default to not found
    let mut found_app_id = false;
    let mut app_id_length: u32 = 0;
    let OCTET_STRING_SEARCH_DISTANCE = 10;

    // Search for a SET (0x31) tag followed by a SEQUENCE (0x30) tag, followed by an OCTET STRING (0x04) tag
    // and read the length byte that follows
    for i in 0..OCTET_STRING_SEARCH_DISTANCE {
        if (attestation_app_id_sequence_offset + i + 1 < TBS_MAX_LEN) & !found_app_id {
            if (tbs[attestation_app_id_sequence_offset + i] == 0x31)
                // Skip the byte encoding the length of the SET
                & (tbs[attestation_app_id_sequence_offset + i + 2] == 0x30)
                // Skip the byte encoding the length of the SEQUENCE
                & (tbs[attestation_app_id_sequence_offset + i + 4] == 0x04) {
                app_id_length = tbs[attestation_app_id_sequence_offset + i + 5] as u32; // Read the length byte
                app_id_offset = attestation_app_id_sequence_offset + i + 6; // Skip the OCTET STRING tag and length
                found_app_id = true;
            }
        }
    }

    // Ensure we found the app ID
    assert(found_app_id, "App ID OCTET STRING not found in credential certificate");
    assert(app_id_offset < TBS_MAX_LEN, "App ID not found in credential certificate");
    assert(app_id_length <= APP_ID_MAX_LEN, "App ID length exceeds maximum allowed length");

    // Extract the app ID with dynamic length, padding with zeros if needed
    let mut app_id = [0u8; APP_ID_MAX_LEN];
    for i in 0..APP_ID_MAX_LEN {
        if i < app_id_length {
            app_id[i] = tbs[app_id_offset + i];
        }
    }

    (app_id, app_id_length)
}

pub fn get_key_origin_from_credential_tbs<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> u8 {
    // Find Android Key Attestation extension OID in the TBS certificate
    let oid_offset = find_subarray_index(OID_ANDROID_KEY_ATTESTATION, tbs);
    assert(
        oid_offset < TBS_MAX_LEN,
        "Android Key Attestation OID not found in credential certificate",
    );

    // Look for the key origin in the TBS certificate
    let key_origin_offset = oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + 1;
    assert(key_origin_offset < TBS_MAX_LEN, "Key origin not found in credential certificate");

    // Read the key origin
    let mut key_origin_offset = TBS_MAX_LEN; // Default to not found
    let mut found_key_origin = false;
    // There are lot of possible extensions in the TBS certificate, so we need to search for the key origin
    // in a large distance
    let KEY_ORIGIN_SEARCH_DISTANCE = 400;
    // Search for the key origin tag pattern (BF 85 3E) within the extension
    for i in 0..KEY_ORIGIN_SEARCH_DISTANCE {
        if (oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 2 < TBS_MAX_LEN)
            & !found_key_origin {
            if (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i] == 0xBF)
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 1] == 0x85)
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 2] == 0x3E)
                // The length should be 3 bytes (the tag of an integer, length of the integer, and the integer itself)
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 3] == 0x03)
                // The integer tag is 0x02
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 4] == 0x02)
                // The integer should only be 1 byte as it's a small enum
                & (tbs[oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 5] == 0x01) {
                key_origin_offset = oid_offset + OID_ANDROID_KEY_ATTESTATION.len() + i + 6;
                found_key_origin = true;
            }
        }
    }
    assert(found_key_origin, "Key origin not found in credential certificate");
    assert(key_origin_offset < TBS_MAX_LEN, "Key origin offset out of bounds");

    // Read the key origin as an integer
    let key_origin = tbs[key_origin_offset];
    key_origin
}
