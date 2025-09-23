pub mod tests;
pub mod constants;
pub mod param_commit;
pub use commitment::calculate_attestation_registry_leaf;
use constants::{
    AAGUID_DEVELOPMENT, AAGUID_PRODUCTION, APP_ATTEST_ENV_DEVELOPMENT, APP_ATTEST_ENV_PRODUCTION,
    APP_ID_MAX_LEN, AUTH_DATA_MAX_LEN, CLIENT_DATA_HASH_LEN,
};
use sha256;
use sha512::sha384;
use sig_check_ecdsa::verify_nist_p384;
use utils::{get_array_slice, poseidon2_hash_packed};

/// Returns total TLV length (tag + length field + content) for any
/// ASN.1 element using DER/BER **definite-length** encoding with a
/// single-byte tag (tag number field < 31).
pub unconstrained fn unsafe_get_asn1_element_length<let N: u32>(asn1: [u8; N]) -> u32 {
    let tag: u8 = asn1[0];
    let elem_len: u8 = asn1[1];

    // Need at least tag(1) + length(1)
    assert(N >= 2, "TLV too short");
    // Only support single-byte tag number (no high-tag-number 0x1F)
    assert((tag & 0x1F) < 0x1F, "High-tag-number form not supported");
    // BER indefinite-length (0x80) is not supported here
    assert(elem_len != 0x80, "Indefinite length not supported");

    // Short form: content length is in low 7 bits
    if (elem_len & 0x80) == 0 {
        let content_len: u32 = (elem_len & 0x7F) as u32;
        let total: u32 = 2 + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
    // Long form: low 7 bits = number of following length bytes
    else {
        let nlen: u32 = (elem_len & 0x7F) as u32;
        assert(nlen > 0, "Zero length-of-length");
        assert(nlen <= 4, "Length field too large");
        assert(2 + nlen <= N, "Length bytes exceed buffer");
        // Parse big-endian content length
        let mut content_len: u32 = 0;
        for i in 0..nlen {
            content_len = content_len * 256 + (asn1[2 + i] as u32);
        }
        let total: u32 = 2 + nlen + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
}

pub fn check_zero_padding<let N: u32, T>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            assert_eq(padded_array[i], T::default());
        }
    }
}

/// Find the index of the first occurrence of the needle in the haystack
/// Returns the index of the first occurrence of the needle in the haystack
/// Returns HAYSTACK_SIZE if the needle is not found
pub fn find_substring_index<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    // Safety: This is safe because the offset is only used as a starting point
    // to verify the substring exists
    let offsetUnchecked = unsafe { find_substring_index_unsafe(needle, haystack) };
    let mut offset = offsetUnchecked;
    // Check if offset is valid before attempting verification
    if (offsetUnchecked < HAYSTACK_SIZE) & (offsetUnchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offsetUnchecked] != needle[i] {
                offset = HAYSTACK_SIZE;
            }
        }
    } else {
        // If offset is out of bounds, needle was not found
        offset = HAYSTACK_SIZE;
    }
    offset
}

/// Safety: This is safe because the offset is only used as a starting point
/// to verify the substring exists
pub unconstrained fn find_substring_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    let mut result = HAYSTACK_SIZE; // Default to "not found" value
    // Handle edge cases
    if NEEDLE_SIZE == 0 {
        result = 0;
    } else if NEEDLE_SIZE <= HAYSTACK_SIZE {
        // Search for the needle in the haystack
        for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
            let mut found = true;
            for j in 0..NEEDLE_SIZE {
                if haystack[i + j] != needle[j] {
                    found = false;
                    break;
                }
            }
            if found {
                result = i;
                break;
            }
        }
    }
    result
}

#[test]
fn test_find_substring_index_various_cases() {
    // Test case 1: Basic substring at index 3
    let needle1 = [0x04, 0x05, 0x06];
    let haystack1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index1 = find_substring_index(needle1, haystack1);
    assert_eq(index1, 3);

    // Test case 2: Substring at the beginning
    let needle2 = [0x01, 0x02];
    let haystack2 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index2 = find_substring_index(needle2, haystack2);
    assert_eq(index2, 0);

    // Test case 3: Substring at the end
    let needle3 = [0x04, 0x05];
    let haystack3 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index3 = find_substring_index(needle3, haystack3);
    assert_eq(index3, 3);

    // Test case 4: Single byte needle
    let needle4 = [0x03];
    let haystack4 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index4 = find_substring_index(needle4, haystack4);
    assert_eq(index4, 2);

    // Test case 5: Empty needle (should return 0)
    let needle5: [u8; 0] = [];
    let haystack5 = [0x01, 0x02, 0x03, 0x04, 0x05];
    let index5 = find_substring_index(needle5, haystack5);
    assert_eq(index5, 0);

    // Test case 6: Needle not found - completely different bytes
    let needle6 = [0xff, 0xee, 0xdd];
    let haystack6 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index6 = find_substring_index(needle6, haystack6);
    assert_eq(index6, haystack6.len()); // Should equal haystack size

    // Test case 7: Needle larger than haystack
    let needle7 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let haystack7 = [0x01, 0x02, 0x03];
    let index7 = find_substring_index(needle7, haystack7);
    assert_eq(index7, haystack7.len()); // Should equal haystack size

    // Test case 8: Partial match at the end but incomplete
    let needle8 = [0x09, 0x0a, 0x0b];
    let haystack8 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    let index8 = find_substring_index(needle8, haystack8);
    assert_eq(index8, haystack8.len()); // Should equal haystack size

    // Test case 9: Multiple false matches (partial matches)
    let needle9 = [0x01, 0x01, 0x02];
    let haystack9 = [0x01, 0x03, 0x01, 0x04, 0x01, 0x01, 0x03, 0x05, 0x06, 0x07];
    let index9 = find_substring_index(needle9, haystack9);
    assert_eq(index9, haystack9.len()); // Should equal haystack size

    // Test case 10: Needle appears to match but fails verification
    let needle10 = [0x02, 0x03, 0x04];
    let haystack10 = [0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09];
    let index10 = find_substring_index(needle10, haystack10);
    assert_eq(index10, haystack10.len()); // Should equal haystack size
}

pub fn verify_substring_in_string<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) {
    let offset = find_substring_index(needle, haystack);
    assert(offset < HAYSTACK_SIZE, "Needle not found in haystack")
}

#[test]
fn test_verify_substring_in_string() {
    let needle = [0x04, 0x05, 0x06];
    let haystack = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
    verify_substring_in_string(needle, haystack);
}

// ------------------------------------------------------------------------------------------------

/// Check that an ECDSA public key x and y coord exists in a TBS certificate
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    let pubkey_offset = find_substring_index(pubkey_x, tbs);
    for i in 0..PUBKEY_SIZE {
        // This check is already guaranteed by find_substring_index
        // assert(
        //     tbs[i + pubkey_offset] == pubkey_x[i],
        //     "Public key x coord not found in TBS certificate",
        // );
        assert(
            tbs[i + pubkey_offset + PUBKEY_SIZE] == pubkey_y[i],
            "Public key y coord not found in TBS certificate",
        );
    }
}

// ------------------------------------------------------------------------------------------------

/// Extract the 32-byte nonce from Apple's App Attest certificate extension
/// OID: 1.2.840.113635.100.8.2
/// The nonce is stored in an ASN.1 OCTET STRING within the extension
pub fn get_nonce_from_credential_tbs<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> [u8; 32] {
    // Find Apple App Attest nonce extension OID in the TBS certificate
    let oid_offset = find_substring_index(constants::OID_APPLE_NONCE_ID, tbs);
    assert(oid_offset < TBS_MAX_LEN, "Nonce OID not found in credential certificate");
    // Look for OCTET STRING tag (04 20) within the next 10 bytes
    let NONCE_SEARCH_DISTANCE = 10;
    // We need to scan forward from the OID position to find the nonce
    let mut nonce_offset = TBS_MAX_LEN; // Default to not found
    let mut found = false;
    // Search for the OCTET STRING pattern (04 20) which indicates 32 bytes follow
    for i in 0..NONCE_SEARCH_DISTANCE {
        if (tbs[oid_offset + 11 + i] == 0x04) & (tbs[oid_offset + 11 + i + 1] == 0x20) & !found {
            nonce_offset = oid_offset + 11 + i + 2; // Skip the OCTET STRING tag and length
            found = true;
        }
    }
    // Ensure we found the nonce
    assert(nonce_offset < TBS_MAX_LEN, "Nonce not found in credential certificate");
    assert(found, "Nonce not found in credential certificate");
    // Extract the 32-byte nonce
    let mut nonce = [0u8; 32];
    for i in 0..32 {
        nonce[i] = tbs[nonce_offset + i];
    }
    nonce
}

pub unconstrained fn unsafe_calculate_auth_data_length<let AUTH_DATA_MAX_LEN: u32>(
    auth_data: [u8; AUTH_DATA_MAX_LEN],
) -> u32 {
    let mut offset: u32 = 0;
    // Fixed prefix (37 bytes total):
    // - rpIdHash: 32 bytes
    // - flags: 1 byte
    // - signCount: 4 bytes
    offset += 32; // rpIdHash
    let flags = auth_data[offset];
    offset += 1; // flags
    offset += 4; // signCount

    // Check if Attested Credential Data flag (AT) is set (bit 6, value 0x40)
    let AT_FLAG: u8 = 0x40;
    let has_attested_credential_data = (flags & AT_FLAG) != 0;
    if has_attested_credential_data {
        // AAGUID: 16 bytes
        offset += 16;

        // Credential ID Length: 2 bytes (big-endian uint16)
        let credential_id_length = unsafe_be16_at(auth_data, offset);
        offset += 2;

        // Credential ID: variable length
        offset += credential_id_length;

        // Credential Public Key: CBOR-encoded COSE_Key (self-describing length)
        let public_key_length = unsafe_parse_cbor_length_at(auth_data, offset);
        offset += public_key_length;
    }

    // Check if Extensions flag (ED) is set (bit 7, value 0x80)
    let ED_FLAG: u8 = 0x80;
    let has_extensions = (flags & ED_FLAG) != 0;
    if has_extensions {
        // Extensions: CBOR map (self-describing length)
        let extension_length = unsafe_parse_cbor_length_at(auth_data, offset);
        offset += extension_length;
    }

    offset
}

// Helper function to read a big-endian 16-bit integer at given offset
unconstrained fn unsafe_be16_at<let N: u32>(data: [u8; N], offset: u32) -> u32 {
    ((data[offset] as u32) << 8) | (data[offset + 1] as u32)
}

// Parse CBOR data starting at given offset and return the number of bytes consumed
unconstrained fn unsafe_parse_cbor_length_at<let N: u32>(data: [u8; N], offset: u32) -> u32 {
    unsafe_parse_cbor_length_slice(data, offset, N)
}

// Core CBOR parsing logic
unconstrained fn unsafe_parse_cbor_length_slice<let N: u32>(
    cbor_bytes: [u8; N],
    start_offset: u32,
    _max_len: u32,
) -> u32 {
    let mut offset = start_offset;
    let first_byte = cbor_bytes[offset];
    let major_type = (first_byte >> 5) & 0x7;
    let additional_info = first_byte & 0x1f;

    offset += 1; // First byte

    // Handle additional information for length encoding
    let mut length: u32 = 0;
    if additional_info < 24 {
        length = additional_info as u32;
    } else if additional_info == 24 {
        length = cbor_bytes[offset] as u32;
        offset += 1;
    } else if additional_info == 25 {
        length = ((cbor_bytes[offset] as u32) << 8) | (cbor_bytes[offset + 1] as u32);
        offset += 2;
    } else if additional_info == 26 {
        length = ((cbor_bytes[offset] as u32) << 24)
            | ((cbor_bytes[offset + 1] as u32) << 16)
            | ((cbor_bytes[offset + 2] as u32) << 8)
            | (cbor_bytes[offset + 3] as u32);
        offset += 4;
    } else if additional_info == 27 {
        // 64-bit length - for simplicity, assume it fits in 32 bits
        offset += 4; // Skip high 32 bits
        length = ((cbor_bytes[offset] as u32) << 24)
            | ((cbor_bytes[offset + 1] as u32) << 16)
            | ((cbor_bytes[offset + 2] as u32) << 8)
            | (cbor_bytes[offset + 3] as u32);
        offset += 4;
    }

    // Handle different major types
    if major_type == 0 {
        // Unsigned integer - length already handled above
    } else if major_type == 1 {
        // Negative integer - length already handled above
    } else if major_type == 2 {
        // Byte string
        offset += length;
    } else if major_type == 3 {
        // Text string
        offset += length;
    } else if major_type == 4 {
        // Array
        for _i in 0..length {
            let item_length = unsafe_parse_cbor_length_slice(cbor_bytes, offset, N);
            offset += item_length;
        }
    } else if major_type == 5 {
        // Map - each entry has key + value
        for _i in 0..length {
            // Parse key
            let key_length = unsafe_parse_cbor_length_slice(cbor_bytes, offset, N);
            offset += key_length;
            // Parse value
            let value_length = unsafe_parse_cbor_length_slice(cbor_bytes, offset, N);
            offset += value_length;
        }
    } else if major_type == 6 {
        // Tag - skip tag, parse tagged value
        let tagged_length = unsafe_parse_cbor_length_slice(cbor_bytes, offset, N);
        offset += tagged_length;
    } else if major_type == 7 {
        // Float/simple/break - length already handled above
    }

    offset - start_offset
}

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

/// Extract the app ID from Apple's App Attest certificate extension
/// OID: 1.2.840.113635.100.8.5
/// The app ID is stored in the 6th item of the sequence as an ASN.1 OCTET STRING
/// The length is determined dynamically from the ASN.1 encoding
/// Returns (app_id_array, actual_length)
pub fn get_app_id_from_credential_tbs<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> ([u8; APP_ID_MAX_LEN], u32) {
    // Find Apple App Attest app ID extension OID in the TBS certificate
    let oid_offset = find_substring_index(constants::OID_APPLE_APP_ID, tbs);
    assert(oid_offset < TBS_MAX_LEN, "App ID OID not found in credential certificate");

    // Look for the 6th item in the sequence (tagged with BF 89 34)
    // The 6th item contains the app ID as an OCTET STRING
    let APP_ID_SEARCH_DISTANCE = 200; // Search within 200 bytes after the OID

    let mut sixth_item_offset = TBS_MAX_LEN; // Default to not found
    let mut found_sixth_item = false;
    // Search for the sixth item tag pattern (BF 89 34) within the extension
    for i in 0..APP_ID_SEARCH_DISTANCE {
        if (oid_offset + 11 + i + 2 < TBS_MAX_LEN) & !found_sixth_item {
            if (tbs[oid_offset + 11 + i] == 0xbf)
                & (tbs[oid_offset + 11 + i + 1] == 0x89)
                & (tbs[oid_offset + 11 + i + 2] == 0x34) {
                sixth_item_offset = oid_offset + 11 + i + 3; // Skip the tag
                found_sixth_item = true;
            }
        }
    }
    assert(found_sixth_item, "Sixth item not found in app ID extension");
    assert(sixth_item_offset < TBS_MAX_LEN, "Sixth item offset out of bounds");

    // Look for OCTET STRING tag (0x04) and read the length dynamically
    let mut app_id_offset = TBS_MAX_LEN; // Default to not found
    let mut found_app_id = false;
    let mut app_id_length: u32 = 0;
    let OCTET_STRING_SEARCH_DISTANCE = 10;

    // Search for the OCTET STRING tag (0x04) and read the length byte that follows
    for i in 0..OCTET_STRING_SEARCH_DISTANCE {
        if (sixth_item_offset + i + 1 < TBS_MAX_LEN) & !found_app_id {
            if tbs[sixth_item_offset + i] == 0x04 {
                app_id_length = tbs[sixth_item_offset + i + 1] as u32; // Read the length byte
                app_id_offset = sixth_item_offset + i + 2; // Skip the OCTET STRING tag and length
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
        // else leave as 0 (already initialized)
    }

    (app_id, app_id_length)
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

pub fn verify_environment<let AUTH_DATA_MAX_LEN: u32>(
    environment: u8,
    auth_data: [u8; AUTH_DATA_MAX_LEN],
) -> bool {
    let mut verified = false;
    // Verify the AAGUID in auth_data matches the environment specified (development or production)
    let aaguid = get_aaguid_from_auth_data(auth_data);
    if environment == APP_ATTEST_ENV_PRODUCTION {
        if aaguid == AAGUID_PRODUCTION {
            verified = true;
        }
    } else if environment == APP_ATTEST_ENV_DEVELOPMENT {
        if aaguid == AAGUID_DEVELOPMENT {
            verified = true;
        }
    }
    verified
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

pub fn verify_auth_data_and_client_data<let CREDENTIAL_TBS_MAX_LEN: u32, let AUTH_DATA_MAX_LEN: u32, let CLIENT_DATA_LEN: u32>(
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    auth_data: [u8; AUTH_DATA_MAX_LEN],
    client_data: [u8; CLIENT_DATA_LEN],
) -> bool {
    // Calculate the client data hash (packed le bytes poseidon2 hash)
    // Safety: This is safe because it only calculates the length of client_data to use for hashing
    // The constrained code later verifies that this hash is bound to the nonce in the signed data
    let client_data_len = unsafe { unsafe_get_asn1_element_length(client_data) };
    let client_data_hash: [u8; CLIENT_DATA_HASH_LEN] =
        get_client_data_hash(client_data, client_data_len);

    // Recalculate nonce from auth_data and client_data_hash
    // Safety: This is safe because it only calculates the length of auth_data to use for hashing
    // The constrained code later verifies that this hash is bound to the nonce in the signed data
    let auth_data_len = unsafe { unsafe_calculate_auth_data_length(auth_data) };
    assert(auth_data_len > 0, "Invalid auth data length");
    assert(auth_data_len <= AUTH_DATA_MAX_LEN, "Invalid auth data length");

    // Verify the recalculated nonce matches the nonce in the credential certificate
    let mut concatenated = [0u8; AUTH_DATA_MAX_LEN + CLIENT_DATA_HASH_LEN];
    for i in 0..AUTH_DATA_MAX_LEN {
        if (i < auth_data_len) {
            concatenated[i] = auth_data[i];
        }
    }
    for i in 0..CLIENT_DATA_HASH_LEN {
        concatenated[auth_data_len + i] = client_data_hash[i];
    }
    let calculated_nonce =
        sha256::sha256_var(concatenated, (auth_data_len + CLIENT_DATA_HASH_LEN) as u64);
    let nonce = get_nonce_from_credential_tbs(credential_tbs);
    calculated_nonce == nonce
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

pub fn get_aaguid_from_auth_data<let AUTH_DATA_MAX_LEN: u32>(
    auth_data: [u8; AUTH_DATA_MAX_LEN],
) -> [u8; 16] {
    get_array_slice::<_, 16>(auth_data, 37)
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
