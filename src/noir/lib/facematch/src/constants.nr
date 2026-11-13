pub global AUTH_DATA_MAX_LEN: u32 = 180;
pub global CREDENTIAL_TBS_MAX_LEN: u32 = 1000;
pub global CLIENT_DATA_MAX_LEN: u32 = 169;
pub global CLIENT_DATA_HASH_LEN: u32 = 32;
pub global APP_ID_MAX_LEN: u32 = 100;
pub global DG2_HASH_MAX_LEN: u32 = 64;

pub global APP_ATTEST_ENV_DEVELOPMENT: u8 = 0x00;
pub global APP_ATTEST_ENV_PRODUCTION: u8 = 0x01;

pub global FACEMATCH_MODE_REGULAR: u8 = 0x01;
pub global FACEMATCH_MODE_STRICT: u8 = 0x02;

pub global MAX_FIELD_BYTES: u32 = 31;

pub global ATTESTATION_KEY_TYPE_APPLE: u8 = 1;
pub global ATTESTATION_KEY_TYPE_GOOGLE: u8 = 2;

// ZKPassportAppAttest attestationType: a face match against a chip's DG2 hash, or a camera-read
// ID whose digest the device computed itself. Kept apart so one can never stand for the other.
pub global ATTESTATION_TYPE_FACE_MATCH: u8 = 1;
pub global ATTESTATION_TYPE_ATTESTED_ID: u8 = 3;
