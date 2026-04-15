pub mod tests;

/// Check that an RSA public key exists in a certificate TBS
pub fn verify_rsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; PUBKEY_SIZE],
    exponent: u32,
    tbs: [u8; TBS_SIZE],
) {
    let pubkey_offset = utils::find_subarray_index(pubkey, tbs);
    for i in 0..PUBKEY_SIZE {
        assert(tbs[i + pubkey_offset] == pubkey[i], "Public key of DSC not found in TBS");
    }
    // Inside the RSAPublicKey ASN.1 SEQUENCE, the publicExponent INTEGER immediately
    // follows the modulus, so the next bytes in the TBS are:
    //   0x02 (INTEGER tag) | <length byte> | <exponent bytes>
    // Decode the length-prefixed big-endian bytes into a u32 and compare against the
    // provided `exponent` parameter.
    let exp_start = pubkey_offset + PUBKEY_SIZE;
    assert(tbs[exp_start] == 0x02, "Exponent INTEGER tag not found after pubkey");
    let exponent_bytes_length = tbs[exp_start + 1] as u32;
    assert(exponent_bytes_length >= 1, "Exponent length must be at least 1 byte");
    assert(exponent_bytes_length <= 4, "Exponent cannot be greater than 4 bytes");
    let mut decoded: u32 = 0;
    for i in 0..4 {
        if i < exponent_bytes_length {
            decoded = decoded * 256 + tbs[exp_start + 2 + i] as u32;
        }
    }
    assert(decoded == exponent, "Exponent of DSC does not match");
}

/// Check that an ECDSA public key x and y coord exists in a certificate TBS
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    let pubkey_offset = utils::find_subarray_index(pubkey_x, tbs);
    for i in 0..PUBKEY_SIZE {
        // We only need to check that the y coord is found after the x coord, since
        // find_substring_index() already guarantees that the x coord exists in the TBS
        assert(
            tbs[i + pubkey_offset + PUBKEY_SIZE] == pubkey_y[i],
            "Public key y coord not found in TBS",
        );
    }
}
