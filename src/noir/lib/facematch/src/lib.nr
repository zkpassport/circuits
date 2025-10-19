use constants::CLIENT_DATA_HASH_LEN;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sha256;
use sha512::sha384;
use sig_check_ecdsa::verify_nist_p384;
use utils::{check_zero_padding, poseidon2_hash_packed, unsafe_get_asn1_element_length};

pub mod android;
pub mod ios;
pub mod constants;
pub mod param_commit;
pub use commitment::calculate_attestation_registry_leaf;

/// Extract the notBefore date from a certificate TBS
/// The notBefore date is the first time value in the validity sequence
/// Supports both UTCTime (13 bytes) and GeneralizedTime (15 bytes)
/// Returns a 14-byte array with the time data in YYYYMMDDhhmmss format (UTCTime is converted to GeneralizedTime format and the Z is dropped)
pub fn get_tbs_not_before_date<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> [u8; 14] {
    // Look for the validity sequence pattern: 0x30 (SEQUENCE) followed by length
    // The validity sequence contains two time values: notBefore and notAfter
    // UTCTime is encoded as: 0x17 (tag) 0x0d (length = 13) followed by 13 bytes of date
    // GeneralizedTime is encoded as: 0x18 (tag) 0x0f (length = 15) followed by 15 bytes of date
    let mut validity_offset = TBS_MAX_LEN; // Default to not found
    let mut found_validity = false;
    let mut is_utc_time = false; // Track if we found UTCTime vs GeneralizedTime
    // Search for validity sequence patterns
    let MAX_VALIDITY_SEQ_SIZE = 36;
    for i in 0..(TBS_MAX_LEN - MAX_VALIDITY_SEQ_SIZE) {
        if !found_validity {
            // Look for UTCTime validity sequence: 0x30 0x1e (SEQUENCE, length 30)
            if (tbs[i] == 0x30) & (tbs[i + 1] == 0x1e) {
                // Look for UTCTime pattern right after: 0x17 0x0d
                if (tbs[i + 2] == 0x17) & (tbs[i + 3] == 0x0d) {
                    validity_offset = i + 4; // Skip SEQUENCE header and UTCTime header
                    is_utc_time = true;
                    found_validity = true;
                }
            }
            // Look for GeneralizedTime validity sequence: 0x30 0x22 (SEQUENCE, length 34)
            else if (tbs[i] == 0x30) & (tbs[i + 1] == 0x22) {
                // Look for GeneralizedTime pattern right after: 0x18 0x0f
                if (tbs[i + 2] == 0x18) & (tbs[i + 3] == 0x0f) {
                    validity_offset = i + 4; // Skip SEQUENCE header and GeneralizedTime header
                    is_utc_time = false;
                    found_validity = true;
                }
            }
        }
    }
    // Ensure we found the validity sequence
    assert(found_validity, "Validity sequence not found in TBS");
    assert(validity_offset < TBS_MAX_LEN, "NotBefore date not found in TBS");

    let mut not_before_date = [0u8; 14];
    if is_utc_time {
        // Convert UTCTime (YYMMDDhhmmssZ) to GeneralizedTime format (YYYYMMDDhhmmssZ)
        // UTCTime years 00-49 represent 2000-2049, years 50-99 represent 1950-1999
        let year_tens = tbs[validity_offset];
        // Determine century based on the year
        // Years 00-49 (0x30-0x34 tens digit) -> 20xx
        // Years 50-99 (0x35-0x39 tens digit) -> 19xx
        if year_tens < 0x35 {
            // 00-49 -> 20xx
            not_before_date[0] = 0x32; // '2'
            not_before_date[1] = 0x30; // '0'
        } else {
            // 50-99 -> 19xx
            not_before_date[0] = 0x31; // '1'
            not_before_date[1] = 0x39; // '9'
        }
        // Copy the rest of the UTCTime data starting from position 2, excluding the Z (YYMMDDhhmmss)
        for i in 0..12 {
            not_before_date[i + 2] = tbs[validity_offset + i];
        }
    } else {
        // GeneralizedTime - copy directly, excluding the Z (YYYYMMDDhhmmss)
        for i in 0..14 {
            not_before_date[i] = tbs[validity_offset + i];
        }
    }
    not_before_date
}

/// Extract the dg2 hash from App Attestation clientData (ZKPassportAppAttest)
/// Parses the DER structure: ZKPassportAppAttest.AttestationData.FaceMatchAttestation.dg2Hash.digest
/// Returns (dg2_hash, dg2_hash_len)
pub fn get_dg2_hash_from_client_data<let CLIENT_DATA_LEN: u32>(
    client_data: [u8; CLIENT_DATA_LEN],
) -> ([u8; 64], u32) {
    // Parse the top-level SEQUENCE (ZKPassportAppAttest)
    assert(client_data[0] == 0x30, "Expected SEQUENCE tag for ZKPassportAppAttest");
    let mut offset = 1; // Start after the SEQUENCE tag
    // Handle length encoding (short or long form)
    if (client_data[offset] & 0x80) == 0 {
        // Short form: length is directly in the byte
        offset += 1;
    } else {
        // Long form: number of length bytes follows
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length indicator + length bytes
    }
    // Skip version (INTEGER)
    assert(client_data[offset] == 0x02, "Expected INTEGER tag for version");
    offset += 1; // tag
    let version_len = client_data[offset] as u32;
    offset += 1 + version_len; // length + content
    // Skip appVersion (UTF8String)
    assert(client_data[offset] == 0x0c, "Expected UTF8String tag for appVersion");
    offset += 1; // tag
    let app_version_len = client_data[offset] as u32;
    offset += 1 + app_version_len; // length + content
    // Skip attestationType (ENUMERATED)
    assert(client_data[offset] == 0x0a, "Expected ENUMERATED tag for attestationType");
    offset += 1; // tag
    let attest_type_len = client_data[offset] as u32;
    offset += 1 + attest_type_len; // length + content
    // Parse AttestationData [1] EXPLICIT FaceMatchAttestation
    assert(client_data[offset] == 0xa1, "Expected [1] EXPLICIT tag for FaceMatchAttestation");
    offset += 1; // tag
    // Handle long form length for AttestationData
    if (client_data[offset] & 0x80) != 0 {
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length encoding
    } else {
        offset += 1; // short form length
    }
    // Parse FaceMatchAttestation SEQUENCE
    assert(client_data[offset] == 0x30, "Expected SEQUENCE tag for FaceMatchAttestation");
    offset += 1; // tag
    // Handle long form length for FaceMatchAttestation
    if (client_data[offset] & 0x80) != 0 {
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length encoding
    } else {
        offset += 1; // short form length
    }
    // Skip mode (ENUMERATED)
    assert(client_data[offset] == 0x0a, "Expected ENUMERATED tag for mode");
    offset += 1; // tag
    let mode_len = client_data[offset] as u32;
    offset += 1 + mode_len; // length + content
    // Parse dg2Hash (DigestInfo SEQUENCE)
    assert(client_data[offset] == 0x30, "Expected SEQUENCE tag for DigestInfo");
    offset += 1; // tag
    offset += 1; // skip length (we don't need it)
    // Skip AlgorithmIdentifier SEQUENCE
    assert(client_data[offset] == 0x30, "Expected SEQUENCE tag for AlgorithmIdentifier");
    offset += 1; // tag
    let algo_id_len = client_data[offset] as u32;
    offset += 1 + algo_id_len; // length + content
    // Extract digest OCTET STRING
    assert(client_data[offset] == 0x04, "Expected OCTET STRING tag for digest");
    offset += 1; // tag
    let dg2_hash_len = client_data[offset] as u32;
    offset += 1; // length
    // Validate digest length (should be 20, 32, 48, or 64 bytes)
    assert(
        (dg2_hash_len == 20) | (dg2_hash_len == 32) | (dg2_hash_len == 48) | (dg2_hash_len == 64),
        "Invalid digest length",
    );
    // Extract the digest and pad to 64 bytes
    let mut dg2_hash = [0u8; 64];
    for i in 0..64 {
        if i < dg2_hash_len {
            dg2_hash[i] = client_data[offset + i];
        }
        // else leave as 0 (already initialized)
    }
    (dg2_hash, dg2_hash_len)
}

/// Verify that the provided dg2_hash matches the one embedded in client_data
/// Returns true if the hashes match, false otherwise
pub fn verify_dg2_hash_in_client_data<let CLIENT_DATA_LEN: u32>(
    dg2_hash_normalized: Field,
    client_data: [u8; CLIENT_DATA_LEN],
) -> bool {
    // Get the dg2 hash from client data and normalize it
    let (client_data_dg2_hash, dg2_hash_len) = get_dg2_hash_from_client_data(client_data);
    let client_data_dg2_hash_normalized = poseidon2_hash_packed(client_data_dg2_hash, dg2_hash_len);
    // Verify the normalized dg2 hash matches the expected normalized dg2 hash
    dg2_hash_normalized == client_data_dg2_hash_normalized
}

/// Extract the facematch mode from App Attestation clientData (ZKPassportAppAttest)
/// Parses the DER structure: ZKPassportAppAttest.AttestationData.FaceMatchAttestation.mode
/// Returns the mode value (1 for regular, 2 for strict)
pub fn get_facematch_mode_from_client_data<let CLIENT_DATA_LEN: u32>(
    client_data: [u8; CLIENT_DATA_LEN],
) -> u8 {
    // Parse the top-level SEQUENCE (ZKPassportAppAttest)
    assert(client_data[0] == 0x30, "Expected SEQUENCE tag for ZKPassportAppAttest");
    let mut offset = 1; // Start after the SEQUENCE tag
    // Handle length encoding (short or long form)
    if (client_data[offset] & 0x80) == 0 {
        // Short form: length is directly in the byte
        offset += 1;
    } else {
        // Long form: number of length bytes follows
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length indicator + length bytes
    }
    // Skip version (INTEGER)
    assert(client_data[offset] == 0x02, "Expected INTEGER tag for version");
    offset += 1; // tag
    let version_len = client_data[offset] as u32;
    offset += 1 + version_len; // length + content
    // Skip appVersion (UTF8String)
    assert(client_data[offset] == 0x0c, "Expected UTF8String tag for appVersion");
    offset += 1; // tag
    let app_version_len = client_data[offset] as u32;
    offset += 1 + app_version_len; // length + content
    // Skip attestationType (ENUMERATED)
    assert(client_data[offset] == 0x0a, "Expected ENUMERATED tag for attestationType");
    offset += 1; // tag
    let attest_type_len = client_data[offset] as u32;
    offset += 1 + attest_type_len; // length + content
    // Parse AttestationData [1] EXPLICIT FaceMatchAttestation
    assert(client_data[offset] == 0xa1, "Expected [1] EXPLICIT tag for FaceMatchAttestation");
    offset += 1; // tag
    // Handle long form length for AttestationData
    if (client_data[offset] & 0x80) != 0 {
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length encoding
    } else {
        offset += 1; // short form length
    }
    // Parse FaceMatchAttestation SEQUENCE
    assert(client_data[offset] == 0x30, "Expected SEQUENCE tag for FaceMatchAttestation");
    offset += 1; // tag
    // Handle long form length for FaceMatchAttestation
    if (client_data[offset] & 0x80) != 0 {
        let length_bytes = (client_data[offset] & 0x7f) as u32;
        offset += 1 + length_bytes; // skip length encoding
    } else {
        offset += 1; // short form length
    }
    // Extract mode (ENUMERATED)
    assert(client_data[offset] == 0x0a, "Expected ENUMERATED tag for mode");
    offset += 1; // tag
    offset += 1; // length
    // Extract the mode value
    let mode = client_data[offset];
    assert((mode == 1) | (mode == 2), "Invalid mode value");
    mode
}

pub fn split_array<let N: u32>(array: [u8; N * 2]) -> ([u8; N], [u8; N]) {
    let mut array_x = [0 as u8; N];
    let mut array_y = [0 as u8; N];
    for i in 0..N {
        array_x[i] = array[i];
        array_y[i] = array[i + N];
    }
    (array_x, array_y)
}

pub fn get_tbs_hash_sha256<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> [u8; 32] {
    // Get the length of the TBS by decoding the ASN.1
    // Safety: This is safe because the length must be correct for the signature to be valid
    let tbs_len = unsafe { unsafe_get_asn1_element_length(tbs) };
    // Ensure all bytes beyond tbs_len are zero
    check_zero_padding(tbs, tbs_len);
    sha256::sha256_var(tbs, tbs_len as u64)
}

pub fn get_tbs_hash_sha384<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> [u8; 48] {
    // Get the length of the TBS by decoding the ASN.1
    // Safety: This is safe because the length must be correct for the signature to be valid
    let tbs_len = unsafe { unsafe_get_asn1_element_length(tbs) };
    // Ensure all bytes beyond tbs_len are zero
    check_zero_padding(tbs, tbs_len);
    let tbs_vec = BoundedVec::from_parts(tbs, tbs_len);
    sha384::sha384_var(tbs_vec)
}

pub fn get_client_data_hash<let CLIENT_DATA_LEN: u32>(
    client_data: [u8; CLIENT_DATA_LEN],
    client_data_len: u32,
) -> [u8; CLIENT_DATA_HASH_LEN] {
    let hash = poseidon2_hash_packed(client_data, client_data_len);
    // Unpack the field into bytes
    let hash_bytes: [u8; CLIENT_DATA_HASH_LEN] = hash.to_be_bytes();
    hash_bytes
}

pub fn prepare_client_data_hash_for_signature(
    poseidon2_hash_bytes: [u8; CLIENT_DATA_HASH_LEN],
) -> [u8; 32] {
    sha256::sha256_var(poseidon2_hash_bytes, CLIENT_DATA_HASH_LEN as u64)
}

pub fn verify_intermediate_certificate<let TBS_MAX_LEN: u32>(
    root_key_x: [u8; 48],
    root_key_y: [u8; 48],
    intermediate_key_x: [u8; 48],
    intermediate_key_y: [u8; 48],
    intermediate_tbs: [u8; TBS_MAX_LEN],
    intermediate_sig: [u8; 96],
) -> bool {
    // Verify the intermediate certificate public key is in the TBS
    verify_ecdsa_pubkey_in_tbs(intermediate_key_x, intermediate_key_y, intermediate_tbs);
    // Verify the root certificate signed the intermediate certificate
    let (sig_r, sig_s) = split_array(intermediate_sig);
    let msg_hash = get_tbs_hash_sha384(intermediate_tbs);
    verify_nist_p384(root_key_x, root_key_y, sig_r, sig_s, msg_hash)
}

pub fn verify_credential_certificate<let TBS_MAX_LEN: u32>(
    intermediate_key_x: [u8; 48],
    intermediate_key_y: [u8; 48],
    credential_tbs: [u8; TBS_MAX_LEN],
    credential_sig: [u8; 96],
) -> bool {
    // Verify the intermediate certificate signed the credential certificate
    let msg_hash = get_tbs_hash_sha256(credential_tbs);
    let (sig_r, sig_s) = split_array(credential_sig);
    verify_nist_p384(
        intermediate_key_x,
        intermediate_key_y,
        sig_r,
        sig_s,
        msg_hash,
    )
}
