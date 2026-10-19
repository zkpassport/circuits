pub mod tests;

use utils::read_der_length;

/// Check that an RSA public key exists in a certificate TBS, bound to its
/// SubjectPublicKeyInfo DER framing.
///
/// Rather than accepting an arbitrary prover-chosen window that happens to be
/// followed by an INTEGER tag, this pins the modulus to the one structurally valid
/// position: the `rsaEncryption` AlgorithmIdentifier is located with a strict
/// first-occurrence search, then the BIT STRING / RSAPublicKey SEQUENCE / modulus
/// INTEGER framing is walked, and the modulus length is bound to the key size.
pub fn verify_rsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; PUBKEY_SIZE],
    exponent: u32,
    tbs: [u8; TBS_SIZE],
) {
    // Anchor on the rsaEncryption OID element itself (1.2.840.113549.1.1.1):
    //   0x06 0x09 | 2A 86 48 86 F7 0D 01 01 01
    // This DER-encoded OID appears only in the SubjectPublicKeyInfo AlgorithmIdentifier
    // (the signature AlgorithmIdentifier uses sha*WithRSAEncryption, whose OID ends in a
    // distinct final byte, e.g. ...01 01 0B), so anchoring on it ties the located modulus
    // to its SPKI "key" role AND to the RSA algorithm, instead of accepting any byte
    // window the prover points at somewhere inside the (country-CA-signed) cert body.
    //
    // NOTE: we anchor on the OID element rather than the full `SEQUENCE { OID, NULL }`
    // wrapper because the NULL parameters, while required by RFC 5280, are omitted by
    // some real-world (HSM-generated) certificates. Binding the fixed-length wrapper
    // would reject those otherwise-valid certs (observed in the ICAO master list).
    let rsaenc_oid: [u8; 11] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    // Strict, first-occurrence search so the key region is pinned to the real SPKI
    // rather than a prover-chosen window elsewhere in the TBS.
    //
    // NOTE: first-occurrence is what matters here. In a TBSCertificate the
    // subjectPublicKeyInfo comes before the `extensions` field (extensions are the
    // last element of the TBS), so a colluding issuer that planted a second
    // rsaEncryption SPKI blob inside an extension could not be selected: the strict
    // search always lands on the genuine SPKI, which necessarily appears first.
    let rsaenc_oid_offset: u32 = utils::find_subarray_index_strict(rsaenc_oid, tbs);
    assert(rsaenc_oid_offset < TBS_SIZE, "rsaEncryption SPKI not found in TBS");

    // The subjectPublicKey BIT STRING follows the AlgorithmIdentifier and wraps the
    // RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    let mut p: u32 = rsaenc_oid_offset + rsaenc_oid.len();
    // Skip the optional NULL parameters (05 00) when the issuer included them; some
    // conformant-enough certs omit them and run the BIT STRING straight after the OID.
    if tbs[p] == 0x05 {
        assert(tbs[p + 1] == 0x00, "Malformed NULL parameters in SPKI");
        p += 2;
    }

    assert(tbs[p] == 0x03, "BIT STRING tag not found in SPKI");
    let (_, bitstr_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + bitstr_len_bytes;

    assert(tbs[p] == 0x00, "BIT STRING unused-bits octet must be zero");
    p += 1;

    assert(tbs[p] == 0x30, "RSAPublicKey SEQUENCE tag not found");
    let (_, seq_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + seq_len_bytes;

    // modulus INTEGER
    assert(tbs[p] == 0x02, "Modulus INTEGER tag not found");
    let (modulus_len, mod_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + mod_len_bytes;

    // A conformant RSA modulus has its top bit set, so DER prepends exactly one 0x00
    // byte, making the INTEGER content PUBKEY_SIZE + 1 bytes. Binding the length byte
    // forbids a shorter (e.g. leading-zero-collapsed) window from being accepted as a
    // full-size modulus.
    assert(modulus_len == PUBKEY_SIZE + 1, "Modulus length does not match key size");
    assert(tbs[p] == 0x00, "Modulus leading zero byte missing");
    p += 1;

    // The modulus bytes must equal the claimed public key, at this structurally
    // pinned position.
    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + i] == pubkey[i], "Public key of DSC not found in TBS");
    }

    // Inside the RSAPublicKey ASN.1 SEQUENCE, the publicExponent INTEGER immediately
    // follows the modulus, so the next bytes in the TBS are:
    //   0x02 (INTEGER tag) | <length byte> | <exponent bytes>
    // Decode the length-prefixed big-endian bytes into a u32 and compare against the
    // provided `exponent` parameter.
    let exp_start: u32 = p + PUBKEY_SIZE;
    assert(tbs[exp_start] == 0x02, "Exponent INTEGER tag not found after pubkey");
    let exponent_bytes_length: u32 = tbs[exp_start + 1] as u32;
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

/// Check that an ECDSA public key x and y coord exists in a certificate TBS, bound
/// to its SubjectPublicKeyInfo DER framing.
///
/// As with the RSA variant, this pins the located point to the one structurally
/// valid position rather than accepting a prover-chosen window: the id-ecPublicKey
/// AlgorithmIdentifier is located with a strict first-occurrence search, the
/// named-curve OID is skipped, and the point is read from the BIT STRING behind its
/// uncompressed-point prefix with the length bound to the key size.
///
/// The specific named curve is intentionally NOT bound here (it is not derivable
/// from PUBKEY_SIZE); the curve is enforced by the curve-specialized ECDSA verifier
/// downstream, including its on-curve check. Both parameter encodings are accepted:
/// a named-curve OID and an explicit ECParameters SEQUENCE. The latter is common in
/// real-world master lists (notably for brainpool curves), so binding only to a
/// named-curve OID would reject a large fraction of legitimate certificates.
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    // The id-ecPublicKey OID (1.2.840.10045.2.1) identifies the key as an EC key and
    // appears only in the SubjectPublicKeyInfo AlgorithmIdentifier (the ECDSA
    // signature OID is distinct), so it anchors the point to its SPKI "key" role.
    let ec_pubkey_oid: [u8; 9] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    // Strict, first-occurrence search. As with RSA, subjectPublicKeyInfo precedes the
    // `extensions` field in a TBSCertificate, so a planted second EC SPKI inside an
    // extension cannot be selected: the genuine SPKI always appears first.
    let ec_pubkey_oid_offset: u32 = utils::find_subarray_index_strict(ec_pubkey_oid, tbs);
    assert(ec_pubkey_oid_offset < TBS_SIZE, "ecPublicKey SPKI not found in TBS");

    // Skip the AlgorithmIdentifier parameters that follow ecPublicKey. This is a
    // single element: either a named-curve OID (0x06) or an explicit ECParameters
    // SEQUENCE (0x30, common for brainpool). Bind only the element framing, not its
    // tag, so both encodings are accepted; the actual curve is enforced downstream.
    let mut p: u32 = ec_pubkey_oid_offset + ec_pubkey_oid.len();
    assert((tbs[p] == 0x06) | (tbs[p] == 0x30), "EC params element not found in SPKI");
    let (params_len, params_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + params_len_bytes + params_len;

    // The subjectPublicKey BIT STRING holds: the unused-bits octet (0x00), the
    // uncompressed-point prefix (0x04), then the x and y coordinates.
    assert(tbs[p] == 0x03, "BIT STRING tag not found in SPKI");
    let (bitstr_len, bitstr_len_bytes) = read_der_length(tbs, p + 1);
    p += 1 + bitstr_len_bytes;
    // 0x00 (unused bits) + 0x04 (uncompressed prefix) + x + y
    assert(bitstr_len == 2 * PUBKEY_SIZE + 2, "EC point length does not match key size");
    assert(tbs[p] == 0x00, "BIT STRING unused-bits octet must be zero");
    p += 1;
    assert(tbs[p] == 0x04, "Uncompressed-point prefix not found");
    p += 1;

    // The x and y coordinates must equal the claimed public key, at this
    // structurally pinned position.
    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + i] == pubkey_x[i], "Public key x coord not found in TBS");
    }
    for i in 0..PUBKEY_SIZE {
        assert(tbs[p + PUBKEY_SIZE + i] == pubkey_y[i], "Public key y coord not found in TBS");
    }
}
