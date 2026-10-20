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
/// Assumes a single-byte tag.
fn skip_element<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let (len, consumed) = read_der_length(tbs, pos + 1);
    pos + 1 + consumed + len
}

/// Number of identifier (tag) octets at `pos`: 1 for the low-tag form, or 1 + the
/// base-128 octets of the high-tag form (low 5 bits == 0x1F) that authorization entries
/// use (e.g. attestationApplicationId [709] = BF 85 45).
fn tag_length<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let mut len: u32 = 1;
    if (tbs[pos] & 0x1F) == 0x1F {
        let mut done: bool = false;
        for i in 0..4 {
            if !done {
                len += 1;
                if (tbs[pos + 1 + i] & 0x80) == 0 {
                    done = true;
                }
            }
        }
    }
    len
}

/// Advance past a whole TLV whose tag may be multi-byte (a context-specific
/// authorization entry): skip the identifier octets, then the length field and content.
fn skip_tagged_element<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    let tl: u32 = tag_length(tbs, pos);
    let (len, consumed) = read_der_length(tbs, pos + tl);
    pos + tl + consumed + len
}

/// Assert the single-byte-tag TLV at `pos` carries `tag`, then descend into its content.
fn expect_enter<let N: u32>(tbs: [u8; N], pos: u32, tag: u8) -> u32 {
    assert(tbs[pos] == tag, "unexpected DER tag while walking credential TBS");
    enter_element(tbs, pos)
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

    // Walk the KeyDescription structurally to confine the app-id search to the
    // CA-attested `softwareEnforced` set: the attacker-chosen `attestationChallenge`
    // (field 5) precedes it, so a flat scan could match a planted BF 85 45 blob there.
    // Framing: 04 extension OCTET STRING -> 30 KeyDescription -> 6 fixed fields -> 30
    // softwareEnforced.
    let mut p: u32 = oid_offset + OID_ANDROID_KEY_ATTESTATION.len();
    p = expect_enter(tbs, p, 0x04); // extension value OCTET STRING
    p = expect_enter(tbs, p, 0x30); // KeyDescription SEQUENCE
    // Skip the six fixed fields by length, stepping over attestationChallenge.
    for _i in 0..6 {
        p = skip_element(tbs, p);
    }
    // Enter softwareEnforced and bound the app-id search to its contents only.
    assert(tbs[p] == 0x30, "softwareEnforced SEQUENCE not found");
    let (sw_len, sw_consumed) = read_der_length(tbs, p + 1);
    let sw_start = p + 1 + sw_consumed;
    let sw_end = sw_start + sw_len;
    assert(sw_end <= TBS_MAX_LEN, "softwareEnforced exceeds certificate bounds");

    // Walk the softwareEnforced entries and match the [709] DER *tag* (BF 85 45),
    // skipping each non-matching entry by length. Only tag positions are inspected, so a
    // value that merely contains those bytes cannot be mistaken for the tag. The entry
    // cap bounds the walk (softwareEnforced holds only a handful of entries).
    let app_id_tag: [u8; 3] = [0xBF, 0x85, 0x45];
    let MAX_SW_ENTRIES: u32 = 32;
    p = sw_start;
    let mut tag_offset: u32 = TBS_MAX_LEN;
    let mut found: bool = false;
    for _ in 0..MAX_SW_ENTRIES {
        if !found & (p + 3 <= sw_end) {
            if (tbs[p] == app_id_tag[0])
                & (tbs[p + 1] == app_id_tag[1])
                & (tbs[p + 2] == app_id_tag[2]) {
                tag_offset = p;
                found = true;
            } else {
                p = skip_tagged_element(tbs, p);
            }
        }
    }
    assert(found, "attestationApplicationId [709] not found in softwareEnforced");

    // Descend [709] (3-byte tag, length at +3): OCTET STRING -> SEQUENCE -> SET ->
    // SEQUENCE -> packageName OCTET STRING (the app id).
    let (_, tag_len_bytes) = read_der_length(tbs, tag_offset + 3);
    let mut q = tag_offset + 3 + tag_len_bytes;
    q = expect_enter(tbs, q, 0x04); // OCTET STRING wrapper
    q = expect_enter(tbs, q, 0x30); // AttestationApplicationId SEQUENCE
    q = expect_enter(tbs, q, 0x31); // SET OF AttestationPackageInfo
    q = expect_enter(tbs, q, 0x30); // AttestationPackageInfo SEQUENCE
    assert(tbs[q] == 0x04, "packageName OCTET STRING not found");
    let (app_id_length, app_id_len_bytes) = read_der_length(tbs, q + 1);
    let app_id_offset = q + 1 + app_id_len_bytes;
    assert(app_id_offset + app_id_length <= TBS_MAX_LEN, "App ID exceeds certificate bounds");
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

// NOTE: unlike the hardened `get_app_id_from_credential_tbs`, this still uses non-strict
// `find_subarray_index` + a flat forward scan over a window that includes the
// attacker-controlled attestationChallenge. NOT currently exploitable: no circuit `main`
// calls it (the `// TODO: Only accept GENERATED` in constants.nr is unwired). If it is
// ever wired into an acceptance path, harden it like `get_app_id`: strict OID anchor +
// structural walk into softwareEnforced before searching for the tag.
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
