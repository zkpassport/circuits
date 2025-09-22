pub global AUTH_DATA_MAX_LEN: u32 = 180;
pub global CREDENTIAL_TBS_MAX_LEN: u32 = 1000;
pub global CLIENT_DATA_MAX_LEN: u32 = 169;
pub global CLIENT_DATA_HASH_LEN: u32 = 32;
pub global APP_ID_MAX_LEN: u32 = 100;
pub global DG2_HASH_MAX_LEN: u32 = 64;

// AAGUID: 617070617474657374646576656c6f70 -> ASCII appattestdevelop (development environment)
pub global AAGUID_DEVELOPMENT: [u8; 16] =
    [97, 112, 112, 97, 116, 116, 101, 115, 116, 100, 101, 118, 101, 108, 111, 112];
// AAGUID: 617070617474657374 -> ASCII appattest (production environment)
pub global AAGUID_PRODUCTION: [u8; 16] =
    [97, 112, 112, 97, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0];

pub global APP_ATTEST_ENV_DEVELOPMENT: u8 = 0x00;
pub global APP_ATTEST_ENV_PRODUCTION: u8 = 0x01;

pub global FACEMATCH_MODE_REGULAR: u8 = 0x01;
pub global FACEMATCH_MODE_STRICT: u8 = 0x02;

// Apple App Attest app ID extension OID: 1.2.840.113635.100.8.5 (DER encoded: 06092a864886f763640805)
pub global OID_APPLE_APP_ID: [u8; 11] =
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x05];
// Apple App Attest nonce extension OID: 1.2.840.113635.100.8.2 (DER encoded: 06092a864886f763640802)
pub global OID_APPLE_NONCE_ID: [u8; 11] =
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];

pub global MAX_FIELD_BYTES: u32 = 31;

pub global ATTESTATION_KEY_TYPE_APPLE: u8 = 1;
pub global ATTESTATION_KEY_TYPE_GOOGLE: u8 = 2;
