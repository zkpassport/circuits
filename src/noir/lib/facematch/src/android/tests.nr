// Auto-generated regression tests for the Android FaceMatch app-identity parser.
// The real credential TBS below is captured from the `android_strict_mode_dev`
// facematch fixture; its attestationApplicationId (in softwareEnforced) is
// "app.zkpassport.zkpassport".
use super::constants::{
    ANDROID_BOOT_KEY_ALLOWLIST_DEPTH, ANDROID_REVOCATION_TREE_DEPTH, KM_SECURITY_LEVEL_STRONGBOX,
    VERIFIED_BOOT_STATE_VERIFIED,
};
use super::{get_app_id_from_credential_tbs, get_key_description, get_tbs_serial_number};
use super::hardware::{
    assert_serial_not_revoked, get_boot_key_allowlist_leaf, is_os_patch_level_recent,
    RevocationProof, verify_hardware_device_state,
};
use poseidon::poseidon2::Poseidon2;
use utils::ordered_mt::OrderedMerkleTreeInclusionProof;

global REAL_CREDENTIAL_TBS: [u8; 1000] = [
    48, 130, 2, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 63,
    49, 18, 48, 16, 6, 3, 85, 4, 10, 19, 9, 83, 116, 114, 111, 110, 103, 66, 111, 120, 49, 41, 48,
    39, 6, 3, 85, 4, 3, 19, 32, 50, 49, 52, 51, 102, 57, 50, 48, 98, 56, 54, 101, 51, 52, 98, 100,
    100, 54, 53, 99, 99, 54, 97, 101, 100, 101, 50, 48, 55, 101, 48, 102, 48, 30, 23, 13, 55, 48,
    48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90, 23, 13, 52, 56, 48, 49, 48, 49, 48, 48, 48, 48, 48,
    48, 90, 48, 31, 49, 29, 48, 27, 6, 3, 85, 4, 3, 19, 20, 65, 110, 100, 114, 111, 105, 100, 32,
    75, 101, 121, 115, 116, 111, 114, 101, 32, 75, 101, 121, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206,
    61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 76, 142, 161, 132, 148, 71, 101,
    172, 205, 118, 196, 252, 134, 68, 108, 217, 41, 187, 27, 245, 211, 127, 239, 23, 90, 158, 82,
    131, 76, 230, 52, 132, 218, 17, 82, 102, 252, 97, 145, 180, 238, 160, 223, 173, 161, 228, 153,
    42, 43, 235, 77, 179, 74, 99, 166, 229, 117, 224, 235, 44, 248, 2, 249, 83, 163, 130, 1, 105,
    48, 130, 1, 101, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 130, 1, 81, 6, 10,
    43, 6, 1, 4, 1, 214, 121, 2, 1, 17, 4, 130, 1, 65, 48, 130, 1, 61, 2, 2, 1, 44, 10, 1, 2, 2, 2,
    1, 44, 10, 1, 2, 4, 36, 100, 98, 57, 48, 48, 97, 49, 97, 45, 97, 55, 50, 99, 45, 52, 55, 49, 98,
    45, 56, 98, 54, 102, 45, 55, 53, 51, 49, 100, 48, 57, 100, 50, 55, 97, 102, 4, 0, 48, 91, 191,
    133, 61, 8, 2, 6, 1, 153, 227, 140, 96, 168, 191, 133, 69, 75, 4, 73, 48, 71, 49, 33, 48, 31, 4,
    25, 97, 112, 112, 46, 122, 107, 112, 97, 115, 115, 112, 111, 114, 116, 46, 122, 107, 112, 97,
    115, 115, 112, 111, 114, 116, 2, 2, 3, 135, 49, 34, 4, 32, 250, 198, 23, 69, 220, 9, 3, 120,
    111, 185, 237, 230, 42, 150, 43, 57, 159, 115, 72, 240, 187, 111, 137, 155, 131, 50, 102, 117,
    145, 3, 59, 156, 48, 129, 167, 161, 8, 49, 6, 2, 1, 2, 2, 1, 3, 162, 3, 2, 1, 3, 163, 4, 2, 2,
    1, 0, 165, 8, 49, 6, 2, 1, 4, 2, 1, 6, 170, 3, 2, 1, 1, 191, 131, 119, 2, 5, 0, 191, 133, 62, 3,
    2, 1, 0, 191, 133, 64, 76, 48, 74, 4, 32, 0, 63, 26, 222, 157, 71, 110, 97, 43, 0, 242, 152, 62,
    106, 215, 220, 209, 94, 106, 128, 204, 45, 187, 0, 141, 167, 214, 131, 158, 215, 58, 143, 1, 1,
    255, 10, 1, 0, 4, 32, 127, 211, 148, 157, 174, 28, 18, 161, 19, 217, 129, 202, 208, 201, 188,
    37, 85, 14, 231, 194, 41, 247, 184, 251, 176, 151, 50, 164, 224, 109, 74, 2, 191, 133, 65, 5, 2,
    3, 2, 34, 224, 191, 133, 66, 5, 2, 3, 3, 22, 169, 191, 133, 78, 6, 2, 4, 1, 52, 218, 9, 191,
    133, 79, 6, 2, 4, 1, 52, 218, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// Byte offset of the attacker-controllable attestationChallenge *content* within the
// TBS above (KeyDescription field 5, which precedes softwareEnforced).
global CHALLENGE_CONTENT_OFFSET: u32 = 309;

// A fully-formed attestationApplicationId marker (BF 85 45 ... package "spoofed"),
// 26 bytes, small enough to fit inside the 36-byte attestationChallenge. A pre-fix
// flat forward scan from the extension OID would encounter this before the genuine
// tag in softwareEnforced and return "spoofed"; the structural walk skips the
// challenge entirely and must ignore it.
global PLANTED_SPOOF_MARKER: [u8; 26] = [
    0xBF, 0x85, 0x45, 0x16, // attestationApplicationId [709], len 22
    0x04, 0x14, //             OCTET STRING, len 20
    0x30, 0x12, //             AttestationApplicationId SEQUENCE, len 18
    0x31, 0x0E, //             packages SET, len 14
    0x30, 0x0C, //             AttestationPackageInfo SEQUENCE, len 12
    0x04, 0x07, 0x73, 0x70, 0x6F, 0x6F, 0x66, 0x65, 0x64, // packageName OCTET "spoofed"
    0x02, 0x01, 0x01, //       version INTEGER 1
    0x31, 0x00, //             signatureDigests SET, empty
];

fn expected_app_id() -> ([u8; 32], u32) {
    let s = "app.zkpassport.zkpassport".as_bytes();
    let mut e = [0u8; 32];
    for i in 0..s.len() {
        e[i] = s[i];
    }
    (e, s.len())
}

// Happy path: the genuine app id is read from a real attestation certificate.
#[test]
fn test_get_app_id_real_cert() {
    let (app_id, len): ([u8; 32], u32) = get_app_id_from_credential_tbs(REAL_CREDENTIAL_TBS);
    let (expected, expected_len) = expected_app_id();
    assert(len == expected_len, "app id length mismatch");
    assert(app_id == expected, "app id mismatch");
}

// Regression (facematch Android app-identity finding): a spoof marker planted inside
// the attacker-controlled attestationChallenge must NOT be picked up. The structural
// walk reads the app id from softwareEnforced, so the genuine id is returned and the
// planted "spoofed" is ignored. Pre-fix, the flat scan returned "spoofed".
#[test]
fn test_get_app_id_ignores_planted_challenge() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    for i in 0..PLANTED_SPOOF_MARKER.len() {
        tbs[CHALLENGE_CONTENT_OFFSET + i] = PLANTED_SPOOF_MARKER[i];
    }
    let (app_id, len): ([u8; 32], u32) = get_app_id_from_credential_tbs(tbs);
    let (expected, expected_len) = expected_app_id();
    assert(len == expected_len, "planted challenge changed the app id length");
    assert(app_id == expected, "planted challenge spoofed the app id");
}

global REAL_VERIFIED_BOOT_KEY: [u8; 32] = [
    0, 63, 26, 222, 157, 71, 110, 97, 43, 0, 242, 152, 62, 106, 215, 220, 209, 94, 106, 128, 204,
    45, 187, 0, 141, 167, 214, 131, 158, 215, 58, 143,
];
global REAL_APP_SIGNING_DIGEST: [u8; 32] = [
    250, 198, 23, 69, 220, 9, 3, 120, 111, 185, 237, 230, 42, 150, 43, 57, 159, 115, 72, 240, 187,
    111, 137, 155, 131, 50, 102, 117, 145, 3, 59, 156,
];
// Offsets within REAL_CREDENTIAL_TBS of the deviceLocked and verifiedBootState values
global DEVICE_LOCKED_OFFSET: u32 = 534;
global VERIFIED_BOOT_STATE_OFFSET: u32 = 537;
// 2024-09-15 and 2025-09-15
global SEPT_2024: u64 = 1726358400;
global SEPT_2025: u64 = 1757894400;

#[test]
fn test_get_key_description_real_cert() {
    let description = get_key_description::<_, 32>(REAL_CREDENTIAL_TBS);
    assert(description.attestation_security_level == KM_SECURITY_LEVEL_STRONGBOX);
    assert(description.keymint_security_level == KM_SECURITY_LEVEL_STRONGBOX);
    assert(description.verified_boot_key == REAL_VERIFIED_BOOT_KEY);
    assert(description.device_locked);
    assert(description.verified_boot_state == VERIFIED_BOOT_STATE_VERIFIED);
    assert(description.os_patch_level == 202409);
    assert(description.app_signing_digest == REAL_APP_SIGNING_DIGEST);
    let (expected, expected_len) = expected_app_id();
    assert(description.app_id == expected);
    assert(description.app_id_length == expected_len);
}

#[test]
fn test_get_tbs_serial_number_real_cert() {
    assert(get_tbs_serial_number(REAL_CREDENTIAL_TBS) == 1);
}

#[test]
fn test_hardware_device_state_accepts_locked_oem_device() {
    let description = get_key_description::<_, 32>(REAL_CREDENTIAL_TBS);
    verify_hardware_device_state(
        description,
        0,
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025,
    );
}

#[test(should_fail_with = "Bootloader must be locked")]
fn test_hardware_device_state_rejects_unlocked_bootloader() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    tbs[DEVICE_LOCKED_OFFSET] = 0;
    let description = get_key_description::<_, 32>(tbs);
    verify_hardware_device_state(
        description,
        0,
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025,
    );
}

#[test(should_fail_with = "OS must pass verified boot")]
fn test_hardware_device_state_rejects_unverified_os() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    tbs[VERIFIED_BOOT_STATE_OFFSET] = 2;
    let description = get_key_description::<_, 32>(tbs);
    verify_hardware_device_state(
        description,
        0,
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025,
    );
}

fn allowlist_root_with(boot_key: [u8; 32]) -> Field {
    let mut current = get_boot_key_allowlist_leaf(boot_key);
    for _ in 0..ANDROID_BOOT_KEY_ALLOWLIST_DEPTH {
        current = Poseidon2::hash([current, 0], 2);
    }
    current
}

#[test]
fn test_hardware_device_state_accepts_allowlisted_self_signed_os() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    tbs[VERIFIED_BOOT_STATE_OFFSET] = 1;
    let description = get_key_description::<_, 32>(tbs);
    verify_hardware_device_state(
        description,
        allowlist_root_with(REAL_VERIFIED_BOOT_KEY),
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025,
    );
}

#[test(should_fail_with = "Verified boot key is not on the allowlist")]
fn test_hardware_device_state_rejects_unknown_self_signed_os() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    tbs[VERIFIED_BOOT_STATE_OFFSET] = 1;
    let description = get_key_description::<_, 32>(tbs);
    verify_hardware_device_state(
        description,
        allowlist_root_with([1; 32]),
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025,
    );
}

#[test(should_fail_with = "Security patch level is too old")]
fn test_hardware_device_state_rejects_old_patch() {
    let description = get_key_description::<_, 32>(REAL_CREDENTIAL_TBS);
    verify_hardware_device_state(
        description,
        0,
        0,
        [0; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
        SEPT_2025 + 31 * 24 * 60 * 60,
    );
}

#[test]
fn test_os_patch_level_recency() {
    assert(is_os_patch_level_recent(202409, SEPT_2024));
    assert(is_os_patch_level_recent(202410, SEPT_2024));
    assert(!is_os_patch_level_recent(202411, SEPT_2024));
    assert(is_os_patch_level_recent(202409, SEPT_2025));
    assert(!is_os_patch_level_recent(202408, SEPT_2025));
    assert(!is_os_patch_level_recent(202413, SEPT_2024));
    assert(!is_os_patch_level_recent(202400, SEPT_2024));
}

// A rootOfTrust planted in the attacker-chosen attestationChallenge, claiming an unlocked
// device, must not be read in place of the genuine one in hardwareEnforced
#[test]
fn test_get_key_description_ignores_planted_root_of_trust() {
    let mut tbs = REAL_CREDENTIAL_TBS;
    let planted: [u8; 8] = [0xBF, 0x85, 0x40, 0x05, 0x30, 0x03, 0x01, 0x01];
    for i in 0..planted.len() {
        tbs[CHALLENGE_CONTENT_OFFSET + i] = planted[i];
    }
    let description = get_key_description::<_, 32>(tbs);
    assert(description.device_locked);
    assert(description.verified_boot_key == REAL_VERIFIED_BOOT_KEY);
}

// An ordered tree holding the sentinels 0 and -1 around the revoked serials 5 and 9
fn revocation_tree() -> (Field, [[Field; ANDROID_REVOCATION_TREE_DEPTH]; 4], [Field; 4]) {
    let leaves: [Field; 4] = [0, 5, 9, -1];
    let mut zero = 0;
    let mut zeros = [0; ANDROID_REVOCATION_TREE_DEPTH];
    for i in 0..ANDROID_REVOCATION_TREE_DEPTH {
        zeros[i] = zero;
        zero = Poseidon2::hash([zero, zero], 2);
    }
    let a = Poseidon2::hash([leaves[0], leaves[1]], 2);
    let b = Poseidon2::hash([leaves[2], leaves[3]], 2);
    let mut root = Poseidon2::hash([a, b], 2);
    for i in 2..ANDROID_REVOCATION_TREE_DEPTH {
        root = Poseidon2::hash([root, zeros[i]], 2);
    }
    let mut paths = [zeros; 4];
    for j in 0..4 {
        paths[j][0] = leaves[j ^ 1];
        paths[j][1] = if j < 2 { b } else { a };
    }
    (root, paths, leaves)
}

fn revocation_proof(left_index: u32) -> (Field, RevocationProof) {
    let (root, paths, leaves) = revocation_tree();
    let proof = RevocationProof::new(
        OrderedMerkleTreeInclusionProof {
            leaf: leaves[left_index],
            leaf_index: left_index as Field,
            sibling_path: paths[left_index],
        },
        OrderedMerkleTreeInclusionProof {
            leaf: leaves[left_index + 1],
            leaf_index: (left_index + 1) as Field,
            sibling_path: paths[left_index + 1],
        },
    );
    (root, proof)
}

#[test]
fn test_serial_not_revoked() {
    let (root, proof) = revocation_proof(1);
    assert_serial_not_revoked(root, 7, proof);
}

#[test(should_fail)]
fn test_revoked_serial_rejected() {
    let (root, proof) = revocation_proof(0);
    assert_serial_not_revoked(root, 5, proof);
}

#[test(should_fail)]
fn test_revocation_proof_with_gap_rejected() {
    let (root, paths, leaves) = revocation_tree();
    let proof = RevocationProof::new(
        OrderedMerkleTreeInclusionProof { leaf: leaves[0], leaf_index: 0, sibling_path: paths[0] },
        OrderedMerkleTreeInclusionProof { leaf: leaves[2], leaf_index: 2, sibling_path: paths[2] },
    );
    assert_serial_not_revoked(root, 5, proof);
}
