// TODO: Only accept GENERATED
pub global ANDROID_KEY_ORIGIN_GENERATED: u8 = 0;
pub global ANDROID_KEY_ORIGIN_DERIVED: u8 = 1;
pub global ANDROID_KEY_ORIGIN_IMPORTED: u8 = 2;
pub global ANDROID_KEY_ORIGIN_UNKNOWN: u8 = 3;
pub global ANDROID_KEY_ORIGIN_SECURELY_IMPORTED: u8 = 4;

// OID_ANDROID_KEY_ATTESTATION: 1.3.6.1.4.1.11129.2.1.17 (DER encoded: 060A2B06010401D679020111)
pub global OID_ANDROID_KEY_ATTESTATION: [u8; 12] =
    [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

// global JWS_HEADER: str<15> = "{\"alg\":\"ES256\"}";
// Base64 encoded JWS header: eyJhbGciOiJFUzI1NiJ9
pub global JWS_HEADER_LENGTH: u32 = 20;
pub global JWS_HEADER_BASE64: [u8; 20] =
    [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74, 57];
// Base64 encoded JWS payload separator: .
pub global JWS_PAYLOAD_SEPARATOR: u8 = 46;
pub global JWS_PAYLOAD_LENGTH: u32 = 1366;

// This is the public key used by Play Integrity to sign the integrity token
// It's a P256 key as the signing algorithm is ECDSA with SHA-256 using P-256 as the curve
pub global PLAY_INTEGRITY_PUBLIC_KEY_X: [u8; 32] = [
    107, 48, 114, 237, 199, 76, 241, 189, 65, 24, 76, 66, 69, 105, 215, 118, 99, 120, 95, 228, 115,
    59, 132, 26, 127, 164, 243, 248, 131, 236, 116, 92,
];
pub global PLAY_INTEGRITY_PUBLIC_KEY_Y: [u8; 32] = [
    128, 65, 122, 29, 121, 206, 219, 126, 163, 96, 28, 35, 13, 89, 99, 254, 38, 211, 6, 124, 148,
    77, 5, 49, 23, 104, 193, 198, 191, 90, 73, 156,
];

pub global INTEGRITY_TOKEN_MAX_LENGTH: u32 = 1024;
