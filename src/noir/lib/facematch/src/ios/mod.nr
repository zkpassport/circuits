use crate::constants::{APP_ATTEST_ENV_DEVELOPMENT, APP_ATTEST_ENV_PRODUCTION, CLIENT_DATA_HASH_LEN};
use utils::{find_subarray_index, get_array_slice, unsafe_get_asn1_element_length};
pub mod constants;
use crate::get_client_data_hash;
use constants::{AAGUID_DEVELOPMENT, AAGUID_PRODUCTION, OID_APPLE_APP_ID, OID_APPLE_NONCE_ID};
pub mod tests;

/// Extract the 32-byte nonce from Apple's App Attest certificate extension
/// OID: 1.2.840.113635.100.8.2
/// The nonce is stored in an ASN.1 OCTET STRING within the extension
pub fn get_nonce_from_credential_tbs<let TBS_MAX_LEN: u32>(tbs: [u8; TBS_MAX_LEN]) -> [u8; 32] {
    // Find Apple App Attest nonce extension OID in the TBS certificate
    let oid_offset = find_subarray_index(OID_APPLE_NONCE_ID, tbs);
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

/// Extract the app ID from Apple's App Attest certificate extension
/// OID: 1.2.840.113635.100.8.5
/// The app ID is stored in the 6th item of the sequence as an ASN.1 OCTET STRING
/// The length is determined dynamically from the ASN.1 encoding
/// Returns (app_id_array, actual_length)
pub fn get_app_id_from_credential_tbs<let TBS_MAX_LEN: u32, let APP_ID_MAX_LEN: u32>(
    tbs: [u8; TBS_MAX_LEN],
) -> ([u8; APP_ID_MAX_LEN], u32) {
    // Find Apple App Attest app ID extension OID in the TBS certificate
    let oid_offset = find_subarray_index(OID_APPLE_APP_ID, tbs);
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

pub fn get_aaguid_from_auth_data<let AUTH_DATA_MAX_LEN: u32>(
    auth_data: [u8; AUTH_DATA_MAX_LEN],
) -> [u8; 16] {
    get_array_slice::<_, 16>(auth_data, 37)
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
