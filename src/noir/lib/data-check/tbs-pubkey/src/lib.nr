pub mod tests;

use utils::read_der_length;

/// Check that an RSA public key exists in a certificate TBS, bound to its
/// SubjectPublicKeyInfo DER framing.
///
/// The modulus is pinned to its SPKI position (not an arbitrary prover-chosen window)
/// by anchoring on the rsaEncryption AlgorithmIdentifier and walking the BIT STRING /
/// RSAPublicKey SEQUENCE / modulus INTEGER framing, binding the modulus length to the
/// key size.
pub fn verify_rsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; PUBKEY_SIZE],
    exponent: u32,
    tbs: [u8; TBS_SIZE],
) {
    // Anchor on the rsaEncryption OID element (1.2.840.113549.1.1.1). It appears only
    // in the SPKI AlgorithmIdentifier (signature OIDs differ in their final byte), so
    // it ties the modulus to its SPKI key role. Anchor on the OID, not the
    // SEQUENCE { OID, NULL } wrapper: some real HSM certs omit the NULL params.
    let rsaenc_oid: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    // Strict first-occurrence: subjectPublicKeyInfo precedes `extensions` in the TBS,
    // so a second SPKI planted in an extension can never be selected.
    let rsaenc_oid_offset: u32 = utils::find_subarray_index_strict(rsaenc_oid, tbs);
    assert(rsaenc_oid_offset < TBS_SIZE, "rsaEncryption SPKI not found in TBS");

    let mut p: u32 = rsaenc_oid_offset + rsaenc_oid.len();
    // Skip the optional NULL parameters (05 00) when present.
    if tbs[p] == 0x05 {
        assert(tbs[p + 1] == 0x00, "Malformed NULL parameters in SPKI");
        p += 2;
    }

    // BIT STRING -> unused-bits octet -> RSAPublicKey SEQUENCE -> modulus INTEGER.
    assert(tbs[p] == 0x03, "BIT STRING tag not found in SPKI");
    let (bitstr_len, bitstr_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + bitstr_len_bytes;

    assert(tbs[p] == 0x00, "BIT STRING unused-bits octet must be zero");
    p += 1;

    assert(tbs[p] == 0x30, "RSAPublicKey SEQUENCE tag not found");
    let (seq_len, seq_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + seq_len_bytes;

    assert(tbs[p] == 0x02, "Modulus INTEGER tag not found");
    let (modulus_len, mod_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + mod_len_bytes;

    // DER prepends a 0x00 to the top-bit-set modulus, so content is PUBKEY_SIZE + 1.
    // Binding the length stops a short window passing as a full-size modulus.
    assert(modulus_len == PUBKEY_SIZE + 1, "Modulus length does not match key size");
    assert(tbs[p] == 0x00, "Modulus leading zero byte missing");
    p += 1;

    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + i] == pubkey[i], "Public key of DSC not found in TBS");
    }

    // publicExponent INTEGER follows the modulus: 0x02 | <length> | <big-endian bytes>.
    let exp_start: u32 = p + PUBKEY_SIZE;
    assert(tbs[exp_start] == 0x02, "Exponent INTEGER tag not found after pubkey");
    let exponent_bytes_length: u32 = tbs[exp_start + 1] as u32;
    assert(exponent_bytes_length >= 1, "Exponent length must be at least 1 byte");
    assert(exponent_bytes_length <= 4, "Exponent cannot be greater than 4 bytes");

    // The RSAPublicKey SEQUENCE must span exactly the modulus + exponent TLVs, and the
    // BIT STRING the unused-bits octet + that SEQUENCE
    let modulus_tlv_len: u32 = 1 + mod_len_bytes + modulus_len;
    let exponent_tlv_len: u32 = 2 + exponent_bytes_length;
    assert(seq_len == modulus_tlv_len + exponent_tlv_len, "RSAPublicKey SEQUENCE length mismatch");
    assert(bitstr_len == 1 + 1 + seq_len_bytes + seq_len, "BIT STRING length mismatch");

    let mut decoded: u32 = 0;
    for i in 0..4 {
        if i < exponent_bytes_length {
            decoded = decoded * 256 + tbs[exp_start + 2 + i] as u32;
        }
    }
    assert(decoded == exponent, "Exponent of DSC does not match");
}

/// Check that an ECDSA public key x and y coord exists in a certificate TBS, bound to
/// its SubjectPublicKeyInfo DER framing.
///
/// Mirrors the RSA variant: anchor on id-ecPublicKey, skip the params element, and
/// read the point from the BIT STRING with its length bound to the key size. The named
/// curve is NOT bound here (not derivable from PUBKEY_SIZE); it is enforced, with the
/// on-curve check, by the curve-specialized verifier downstream.
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    // id-ecPublicKey OID (1.2.840.10045.2.1): appears only in the SPKI
    // AlgorithmIdentifier, anchoring the point to its SPKI key role.
    let ec_pubkey_oid: [u8; 9] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    // Strict first-occurrence (see RSA variant): the genuine SPKI precedes `extensions`.
    let ec_pubkey_oid_offset: u32 = utils::find_subarray_index_strict(ec_pubkey_oid, tbs);
    assert(ec_pubkey_oid_offset < TBS_SIZE, "ecPublicKey SPKI not found in TBS");

    // Skip the params element after ecPublicKey: a named-curve OID (0x06) or an explicit
    // ECParameters SEQUENCE (0x30, common for brainpool). Bind only the framing, not the
    // tag, so both encodings are accepted; the curve is enforced downstream.
    let mut p: u32 = ec_pubkey_oid_offset + ec_pubkey_oid.len();
    assert((tbs[p] == 0x06) | (tbs[p] == 0x30), "EC params element not found in SPKI");
    let (params_len, params_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + params_len_bytes + params_len;

    // BIT STRING: unused-bits octet (0x00), uncompressed-point prefix (0x04), x, y.
    assert(tbs[p] == 0x03, "BIT STRING tag not found in SPKI");
    let (bitstr_len, bitstr_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + bitstr_len_bytes;
    assert(bitstr_len == 2 * PUBKEY_SIZE + 2, "EC point length does not match key size");
    assert(tbs[p] == 0x00, "BIT STRING unused-bits octet must be zero");
    p += 1;
    assert(tbs[p] == 0x04, "Uncompressed-point prefix not found");
    p += 1;

    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + i] == pubkey_x[i], "Public key x coord not found in TBS");
    }
    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + PUBKEY_SIZE + i] == pubkey_y[i], "Public key y coord not found in TBS");
    }
}
