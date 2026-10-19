use crate::constants::APP_ID_MAX_LEN;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sha256;
use sha512::sha384;
use sig_check_ecdsa::{verify_nist_p256, verify_nist_p384};
use utils::{
    check_zero_padding, find_subarray_index, find_subarray_index_strict, get_array_slice,
    poseidon2_hash_packed, read_der_length, unsafe_get_asn1_element_length,
};

pub mod constants;
pub mod token;
use constants::{ANDROID_KEY_ORIGIN_GENERATED, OID_ANDROID_KEY_ATTESTATION};
pub mod tests;

/// Advance from a TLV's tag octet (at `pos`) to the start of its content (descend into
/// a constructed element).
fn enter_element<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let (_, consumed) = read_der_length(tbs, pos + 1);
    pos + 1 + consumed
}

/// Advance from a TLV's tag octet (at `pos`) past the whole element (skip it entirely).
fn skip_element<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let (len, consumed) = read_der_length(tbs, pos + 1);
    pos + 1 + consumed + len
}

pub fn get_app_id_from_credential_tbs<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> ([u8; APP_ID_MAX_LEN], u32) {
    // Locate the Android Key Attestation extension OID. Strict first-occurrence so the
    // anchor cannot be pointed at a planted copy inside attacker-controlled bytes.
    let oid_offset = find_subarray_index_strict(OID_ANDROID_KEY_ATTESTATION, tbs);
    assert(
        oid_offset < TBS_MAX_LEN,
        "Android Key Attestation OID not found in credential certificate",
    );

    // Walk the KeyDescription structurally so the app-id search is confined to the
    // CA-attested `softwareEnforced` set. The attacker-chosen `attestationChallenge`
    // (KeyDescription field 5) precedes `softwareEnforced` (field 7) in the signed
    // bytes, so a flat forward scan from the OID would otherwise pick up a BF 85 45 /
    // app-id blob planted inside that challenge (see the facematch app-identity finding).
    //
    //   <OID> 04 <len>              extension value OCTET STRING
    //           30 <len>            KeyDescription SEQUENCE
    //             02 .. attestationVersion       |
    //             0A .. attestationSecurityLevel | six fixed fields skipped by length,
    //             02 .. keymasterVersion         | up to and including the attacker-
    //             0A .. keymasterSecurityLevel   | controlled attestationChallenge and
    //             04 .. attestationChallenge     | uniqueId
    //             04 .. uniqueId                 |
    //             30 <len> softwareEnforced      <- the app id lives in here
    let mut p = oid_offset + OID_ANDROID_KEY_ATTESTATION.len();
    assert(tbs[p] == 0x04, "Attestation extension value not found");
    p = enter_element(tbs, p); // into the extension value OCTET STRING
    assert(tbs[p] == 0x30, "KeyDescription SEQUENCE not found");
    p = enter_element(tbs, p); // into the KeyDescription SEQUENCE
    // Skip the six fixed fields (attestationVersion .. uniqueId); this steps over the
    // attacker-controlled attestationChallenge by its declared length.
    for _i in 0..6 {
        p = skip_element(tbs, p);
    }
    // Enter softwareEnforced and bound the app-id search to its contents only.
    assert(tbs[p] == 0x30, "softwareEnforced SEQUENCE not found");
    let (sw_len, sw_consumed) = read_der_length(tbs, p + 1);
    let sw_start = p + 1 + sw_consumed;
    let sw_end = sw_start + sw_len;
    assert(sw_end <= TBS_MAX_LEN, "softwareEnforced exceeds certificate bounds");

    // Search for the attestationApplicationId [709] tag (BF 85 45) within softwareEnforced.
    let APP_ID_SEARCH_DISTANCE = 200;
    let mut attestation_app_id_sequence_offset = TBS_MAX_LEN; // Default to not found
    let mut found_attestation_app_id_sequence = false;
    for i in 0..APP_ID_SEARCH_DISTANCE {
        let at = sw_start + i;
        if (at + 2 < sw_end) & !found_attestation_app_id_sequence {
            if (tbs[at] == 0xbf) & (tbs[at + 1] == 0x85) & (tbs[at + 2] == 0x45) {
                attestation_app_id_sequence_offset = at + 4; // Skip the 3-byte tag and length
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

// NOTE: like the pre-hardening `get_app_id_from_credential_tbs`, this still uses the
// non-strict `find_subarray_index` plus a flat forward scan, so the BF 85 3E key-origin
// tag is searched over a window that includes the attacker-controlled
// attestationChallenge. It is NOT currently exploitable because no circuit `main` calls
// this function (the `// TODO: Only accept GENERATED` in android/constants.nr is unwired),
// and any use would additionally be gated by the app-id / Play-Integrity path. If this
// is ever wired into an acceptance path, harden it the same way as `get_app_id`: strict
// OID anchor + structural walk into softwareEnforced/teeEnforced (skip attestationChallenge
// and uniqueId by length) before searching for the tag.
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
