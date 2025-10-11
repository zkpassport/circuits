use json_parser::JSON1kb;
use base64::BASE64_DECODER;
use crate::constants::{APP_ATTEST_ENV_DEVELOPMENT, APP_ATTEST_ENV_PRODUCTION, APP_ID_MAX_LEN};

global SAMPLE_INTEGRITY_TOKEN: str<615> = "{\"requestDetails\":{\"requestPackageName\":\"com.package.name\",\"timestampMillis\":\"1617893780\",\"nonce\":\"uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=\"},\"appIntegrity\":{\"appRecognitionVerdict\":\"PLAY_RECOGNIZED\",\"packageName\":\"com.package.name\",\"certificateSha256Digest\":[\"6a6a1474b5cbbb2b1aa57e0bc3\"],\"versionCode\":\"42\"},\"deviceIntegrity\":{\"deviceRecognitionVerdict\":[\"MEETS_DEVICE_INTEGRITY\",\"MEETS_STRONG_INTEGRITY\"],\"recentDeviceActivity\":{\"deviceActivityLevel\":\"LEVEL_3\"},\"deviceAttributes\":{\"sdkVersion\":32}},\"accountDetails\":{\"appLicensingVerdict\":\"LICENSED\"},\"environmentDetails\":{\"playProtectVerdict\":\"NO_ISSUES\"}}";

pub struct IntegrityTokenCheckResponse {
    timestamp: u64,
    environment: u8,
    nonce: [u8; 32],
}

pub fn parse_integrity_token(token: [u8; 1000]) -> JSON1kb {
    let json = JSON1kb::parse_json(token);
    json
}

fn convert_timestamp_string_to_u64(timestamp: BoundedVec<u8, 30>) -> u64 {
    let mut timestamp_u64: u64 = 0;
    for i in 0..30 {
        if i < timestamp.len() {
            // Convert the ASCII character to a number
            let digit = timestamp.get(i) - 0x30;
            timestamp_u64 = timestamp_u64 * 10 + digit as u64;
        }
    }
    timestamp_u64
}

fn decode_nonce(nonce: BoundedVec<u8, 64>) -> BoundedVec<u8, 32> {
    // The nonce is a sha256 hash, so it is 32 bytes
    let decoded_nonce: BoundedVec<u8, 32> = BASE64_DECODER::decode_var(nonce);
    decoded_nonce
}

/// Verify the integrity token from Play Integrity API
/// The integrity token is signed, so the signature can be verified
/// to make sure we can trust it.
/// Structure of the integrity token:
/// {
///   "requestDetails": {
///     "requestPackageName": "com.package.name",
///     // Actually not in milliseconds, but in seconds
///     "timestampMillis": "1617893780",
///     "nonce": "aGVsbG8gd29scmQgdGhlcmU"
///   },
///   "appIntegrity": {
///     "appRecognitionVerdict": "PLAY_RECOGNIZED",
///     "packageName": "com.package.name",
///     "certificateSha256Digest": [
///       "6a6a1474b5cbbb2b1aa57e0bc3"
///     ],
///     "versionCode": "42"
///   },
///   "deviceIntegrity": {
///     "deviceRecognitionVerdict": [
///       "MEETS_DEVICE_INTEGRITY",
///       "MEETS_STRONG_INTEGRITY"
///     ],
///     "recentDeviceActivity": {
///       "deviceActivityLevel": "LEVEL_3"
///     },
///     "deviceAttributes": {
///      "sdkVersion": 32
///     }
///   },
///   "accountDetails": {
///     "appLicensingVerdict": "LICENSED"
///   },
///   "environmentDetails": {
///     "playProtectVerdict": "NO_ISSUES"
///   }
/// }
pub fn verify_integrity_token(token: JSON1kb, app_id: [u8; APP_ID_MAX_LEN], app_id_length: u32) -> IntegrityTokenCheckResponse {
    let request_details = token.get_object("requestDetails").unwrap();
    let request_package_name: BoundedVec<u8, APP_ID_MAX_LEN> = request_details.get_string("requestPackageName").unwrap();
    let timestamp_millis: BoundedVec<u8, 30> = request_details.get_string("timestampMillis").unwrap();
    let nonce: BoundedVec<u8, 64> = request_details.get_string("nonce").unwrap();

    let app_integrity = token.get_object("appIntegrity").unwrap();

    let app_recognition_verdict: BoundedVec<u8, 30> = app_integrity.get_string("appRecognitionVerdict").unwrap();
    // We only accept when the app was downloaded from the Google Play Store 
    // and is recognized by Google as the bundle we originally signed and published
    let pass_app_recognition_verdict = app_recognition_verdict == BoundedVec::from_array("PLAY_RECOGNIZED".as_bytes());
    
    let package_name: BoundedVec<u8, APP_ID_MAX_LEN> = app_integrity.get_string("packageName").unwrap();
    assert_eq(package_name, request_package_name, "Package name mismatch");
    assert_eq(package_name, BoundedVec::from_parts(app_id, app_id_length), "The package name in the token does not match the expected app id");

    let device_integrity = token.get_object("deviceIntegrity").unwrap();
    let device_recognition_verdict = device_integrity.get_array("deviceRecognitionVerdict").unwrap();

    let device_recognition_verdict_len = device_recognition_verdict.get_length();
    let mut passes_device_recognition = false;
    // There are 3 possible device recognition verdicts
    // MEETS_DEVICE_INTEGRITY, MEETS_STRONG_INTEGRITY, MEETS_BASIC_INTEGRITY
    // We only consider MEETS_DEVICE_INTEGRITY and MEETS_STRONG_INTEGRITY
    // MEETS_BASIC_INTEGRITY does not give enough guarantee
    for i in 0..3 {
        if i < device_recognition_verdict_len {
            let device_recognition_verdict: BoundedVec<u8, 30> = device_recognition_verdict.get_string_from_array(i as Field).unwrap();
            if (device_recognition_verdict == BoundedVec::from_array("MEETS_DEVICE_INTEGRITY".as_bytes())) | 
            (device_recognition_verdict == BoundedVec::from_array("MEETS_STRONG_INTEGRITY".as_bytes())) {
                passes_device_recognition = true;
            }
        }
    }

    let environment_details = token.get_object("environmentDetails").unwrap();
    let play_protect_verdict: BoundedVec<u8, 30> = environment_details.get_string("playProtectVerdict").unwrap();
    // TODO: See if this requirement is too strict or not
    let pass_play_protect_verdict = play_protect_verdict == BoundedVec::from_array("NO_ISSUES".as_bytes());

    let pass_all_checks = pass_app_recognition_verdict & passes_device_recognition & pass_play_protect_verdict;

    IntegrityTokenCheckResponse {
        timestamp: convert_timestamp_string_to_u64(timestamp_millis),
        // If all checks pass, we consider the environment to be production
        // Otherwise, we consider the environment to be development which is not accepted by verifiers
        // in production
        environment: if pass_all_checks { APP_ATTEST_ENV_PRODUCTION } else { APP_ATTEST_ENV_DEVELOPMENT },
        nonce: decode_nonce(nonce).storage(),
    }
}

fn pad_token<let TOKEN_LEN: u32>(token: [u8; TOKEN_LEN]) -> [u8; 1000] {
    // Rather than 0s, we use 32s to encode whitespaces
    let mut padded_token = [32; 1000];
    for i in 0..TOKEN_LEN {
        padded_token[i] = token[i];
    }
    padded_token
}

#[test]
fn test_verify_integrity_token() {
    let token = parse_integrity_token(pad_token(SAMPLE_INTEGRITY_TOKEN.as_bytes()));
    let app_id: BoundedVec<u8, APP_ID_MAX_LEN> = BoundedVec::from_array("com.package.name".as_bytes());
    let app_id_length = 16;
    let response = verify_integrity_token(token, app_id.storage(), app_id_length);
    assert_eq(response.environment, APP_ATTEST_ENV_PRODUCTION);
    assert_eq(response.timestamp, 1617893780);
    let hash = sha256::sha256_var("hello world".as_bytes(), 11);
    assert_eq(response.nonce, hash);
}