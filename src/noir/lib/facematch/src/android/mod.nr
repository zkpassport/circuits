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
pub mod hardware;
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

/// Bounds of the two authorization lists of the Android KeyDescription, and the security
/// levels it reports for the attestation and for the key.
struct KeyDescriptionLayout {
    attestation_security_level: u8,
    keymint_security_level: u8,
    software_enforced_start: u32,
    software_enforced_end: u32,
    hardware_enforced_start: u32,
    hardware_enforced_end: u32,
}

fn read_enumerated<let N: u32>(tbs: [u8; N], pos: u32) -> u8 {
    assert((tbs[pos] == 0x0A) & (tbs[pos + 1] == 0x01), "expected a one-byte ENUMERATED");
    tbs[pos + 2]
}

/// Walks the KeyDescription structurally. The attestation OID is anchored on its first
/// occurrence and the attacker-chosen `attestationChallenge` is skipped by length, so no
/// field can be read from bytes the app controls.
/// Framing: 04 extension OCTET STRING -> 30 KeyDescription -> attestationVersion,
/// attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel, attestationChallenge,
/// uniqueId, softwareEnforced, hardwareEnforced.
fn get_key_description_layout<let TBS_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> KeyDescriptionLayout {
    let oid_offset = find_subarray_index_strict(OID_ANDROID_KEY_ATTESTATION, tbs);
    assert(
        oid_offset < TBS_MAX_LEN,
        "Android Key Attestation OID not found in credential certificate",
    );

    let mut p: u32 = oid_offset + OID_ANDROID_KEY_ATTESTATION.len();
    p = expect_enter(tbs, p, 0x04);
    let (description_len, description_consumed) = read_der_length(tbs, p + 1);
    let description_end = p + 1 + description_consumed + description_len;
    assert(description_end <= TBS_MAX_LEN, "KeyDescription exceeds certificate bounds");
    p = expect_enter(tbs, p, 0x30);

    p = skip_element(tbs, p);
    let attestation_security_level = read_enumerated(tbs, p);
    p = skip_element(tbs, p);
    p = skip_element(tbs, p);
    let keymint_security_level = read_enumerated(tbs, p);
    p = skip_element(tbs, p);
    p = skip_element(tbs, p);
    p = skip_element(tbs, p);

    assert(tbs[p] == 0x30, "softwareEnforced SEQUENCE not found");
    let (sw_len, sw_consumed) = read_der_length(tbs, p + 1);
    let software_enforced_start = p + 1 + sw_consumed;
    let software_enforced_end = software_enforced_start + sw_len;
    assert(software_enforced_end <= description_end, "softwareEnforced exceeds KeyDescription");

    p = software_enforced_end;
    assert(tbs[p] == 0x30, "hardwareEnforced SEQUENCE not found");
    let (hw_len, hw_consumed) = read_der_length(tbs, p + 1);
    let hardware_enforced_start = p + 1 + hw_consumed;
    let hardware_enforced_end = hardware_enforced_start + hw_len;
    assert(hardware_enforced_end <= description_end, "hardwareEnforced exceeds KeyDescription");

    KeyDescriptionLayout {
        attestation_security_level,
        keymint_security_level,
        software_enforced_start,
        software_enforced_end,
        hardware_enforced_start,
        hardware_enforced_end,
    }
}

/// Finds the entry with a three-byte context tag in an authorization list, stepping from tag
/// to tag by length so a value that merely contains the tag bytes is never matched.
/// Returns the position of the entry's content.
fn find_authorization_entry<let N: u32>(tbs: [u8; N], start: u32, end: u32, tag: [u8; 3]) -> u32 {
    let MAX_ENTRIES: u32 = 48;
    let mut p = start;
    let mut content_offset: u32 = N;
    let mut found: bool = false;
    for _ in 0..MAX_ENTRIES {
        if !found & (p + 3 <= end) {
            if (tbs[p] == tag[0]) & (tbs[p + 1] == tag[1]) & (tbs[p + 2] == tag[2]) {
                let (len, consumed) = read_der_length(tbs, p + 3);
                content_offset = p + 3 + consumed;
                assert(content_offset + len <= end, "authorization entry exceeds its list");
                found = true;
            } else {
                p = skip_tagged_element(tbs, p);
            }
        }
    }
    assert(found, "authorization entry not found");
    content_offset
}

/// Reads the attestationApplicationId [709] from softwareEnforced, where Keystore records the
/// package name and the digest of the certificate the APK is signed with.
/// Framing: OCTET STRING -> SEQUENCE -> SET OF AttestationPackageInfo -> SEQUENCE ->
/// packageName OCTET STRING, then the SET OF signatureDigests.
fn get_attestation_application_id<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
    layout: KeyDescriptionLayout,
) -> ([u8; APP_ID_MAX_LEN], u32, [u8; 32]) {
    let mut q = find_authorization_entry(
        tbs,
        layout.software_enforced_start,
        layout.software_enforced_end,
        [0xBF, 0x85, 0x45],
    );
    q = expect_enter(tbs, q, 0x04);
    q = expect_enter(tbs, q, 0x30);
    let packages_offset = q;
    q = expect_enter(tbs, q, 0x31);
    q = expect_enter(tbs, q, 0x30);
    assert(tbs[q] == 0x04, "packageName OCTET STRING not found");
    let (app_id_length, app_id_len_bytes) = read_der_length(tbs, q + 1);
    let app_id_offset = q + 1 + app_id_len_bytes;
    assert(app_id_offset + app_id_length <= TBS_MAX_LEN, "App ID exceeds certificate bounds");
    assert(app_id_length <= APP_ID_MAX_LEN, "App ID length exceeds maximum allowed length");

    let mut app_id = [0u8; APP_ID_MAX_LEN];
    for i in 0..APP_ID_MAX_LEN {
        if i < app_id_length {
            app_id[i] = tbs[app_id_offset + i];
        }
    }

    let mut d = skip_element(tbs, packages_offset);
    d = expect_enter(tbs, d, 0x31);
    assert((tbs[d] == 0x04) & (tbs[d + 1] == 32), "signature digest must be a SHA-256 digest");
    assert(d + 2 + 32 <= layout.software_enforced_end, "signature digest exceeds softwareEnforced");
    let mut signing_digest = [0u8; 32];
    for i in 0..32 {
        signing_digest[i] = tbs[d + 2 + i];
    }

    (app_id, app_id_length, signing_digest)
}

pub fn get_app_id_from_credential_tbs<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> ([u8; APP_ID_MAX_LEN], u32) {
    let layout = get_key_description_layout(tbs);
    let (app_id, app_id_length, _) = get_attestation_application_id(tbs, layout);
    (app_id, app_id_length)
}

/// What the Android key attestation says about the device and the app, read from the
/// credential certificate. `device_locked`, `verified_boot_*` and `os_patch_level` come from
/// hardwareEnforced; the package name and signing digest from softwareEnforced.
pub struct AndroidKeyDescription<let APP_ID_MAX_LEN: u32> {
    pub attestation_security_level: u8,
    pub keymint_security_level: u8,
    pub verified_boot_key: [u8; 32],
    pub device_locked: bool,
    pub verified_boot_state: u8,
    /// YYYYMM
    pub os_patch_level: u32,
    pub app_id: [u8; APP_ID_MAX_LEN],
    pub app_id_length: u32,
    pub app_signing_digest: [u8; 32],
}

fn read_small_integer<let N: u32>(tbs: [u8; N], pos: u32) -> u32 {
    assert(tbs[pos] == 0x02, "INTEGER not found");
    let len = tbs[pos + 1] as u32;
    assert((len >= 1) & (len <= 4), "INTEGER too long");
    assert(tbs[pos + 2] < 0x80, "INTEGER must be positive");
    let mut value: u32 = 0;
    for i in 0..4 {
        if i < len {
            value = value * 256 + tbs[pos + 2 + i] as u32;
        }
    }
    value
}

pub fn get_key_description<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> AndroidKeyDescription<APP_ID_MAX_LEN> {
    let layout = get_key_description_layout(tbs);
    let (app_id, app_id_length, app_signing_digest) = get_attestation_application_id(tbs, layout);

    // rootOfTrust [704]: SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
    // verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING }
    let mut r = find_authorization_entry(
        tbs,
        layout.hardware_enforced_start,
        layout.hardware_enforced_end,
        [0xBF, 0x85, 0x40],
    );
    r = expect_enter(tbs, r, 0x30);
    assert((tbs[r] == 0x04) & (tbs[r + 1] == 32), "verifiedBootKey must be 32 bytes");
    let mut verified_boot_key = [0u8; 32];
    for i in 0..32 {
        verified_boot_key[i] = tbs[r + 2 + i];
    }
    r += 34;
    assert((tbs[r] == 0x01) & (tbs[r + 1] == 0x01), "deviceLocked BOOLEAN not found");
    let device_locked = tbs[r + 2] != 0;
    r += 3;
    let verified_boot_state = read_enumerated(tbs, r);
    assert(r + 3 <= layout.hardware_enforced_end, "rootOfTrust exceeds hardwareEnforced");

    let patch_offset = find_authorization_entry(
        tbs,
        layout.hardware_enforced_start,
        layout.hardware_enforced_end,
        [0xBF, 0x85, 0x42],
    );
    let os_patch_level = read_small_integer(tbs, patch_offset);

    AndroidKeyDescription {
        attestation_security_level: layout.attestation_security_level,
        keymint_security_level: layout.keymint_security_level,
        verified_boot_key,
        device_locked,
        verified_boot_state,
        os_patch_level,
        app_id,
        app_id_length,
        app_signing_digest,
    }
}

/// Reads the serial number of a certificate from its TBS, as an integer. Serials are at most
/// 20 octets (RFC 5280), plus a leading zero when the top bit is set, so they fit in a Field.
pub fn get_tbs_serial_number<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> Field {
    let mut p = expect_enter(tbs, 0, 0x30);
    if tbs[p] == 0xA0 {
        p = skip_element(tbs, p);
    }
    assert(tbs[p] == 0x02, "serialNumber INTEGER not found");
    let len = tbs[p + 1] as u32;
    assert((len >= 1) & (len <= 21), "serialNumber too long");
    assert((len < 21) | (tbs[p + 2] == 0), "serialNumber too long");
    let mut serial: Field = 0;
    for i in 0..21 {
        if i < len {
            serial = serial * 256 + tbs[p + 2 + i] as Field;
        }
    }
    serial
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
