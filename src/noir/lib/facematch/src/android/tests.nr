// Auto-generated regression tests for the Android FaceMatch app-identity parser.
// The real credential TBS below is captured from the `android_strict_mode_dev`
// facematch fixture; its attestationApplicationId (in softwareEnforced) is
// "app.zkpassport.zkpassport".
use super::get_app_id_from_credential_tbs;

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
