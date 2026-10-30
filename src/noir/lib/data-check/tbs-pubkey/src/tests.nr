use super::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};

// Offsets inside the TBS built by `tbs_with_rsa_spki` (2048-bit rsaEncryption key).
global SPKI_OFF: u32 = 100; // start of the SubjectPublicKeyInfo SEQUENCE
global MOD_OFF: u32 = 133; // start of the 256 modulus bytes
global EXP_OFF: u32 = 389; // start of the publicExponent TLV (after the modulus)

fn sample_modulus() -> [u8; 256] {
    let mut m = [0 as u8; 256];
    for i in 0..256 {
        m[i] = i as u8;
    }
    m
}

// Build a TBS containing a well-formed rsaEncryption SubjectPublicKeyInfo for a
// 2048-bit modulus. The publicExponent TLV is left for the caller to write at
// EXP_OFF so each test can exercise a different exponent encoding.
fn tbs_with_rsa_spki(modulus: [u8; 256]) -> [u8; 1000] {
    let mut tbs = [0 as u8; 1000];
    // 30 82 01 22                              SPKI SEQUENCE
    //   30 0D 06 09 2A8648 86F70D 010101 0500  AlgId: rsaEncryption + NULL
    //   03 82 01 0F 00                         BIT STRING + unused-bits octet
    //     30 82 01 0A                          RSAPublicKey SEQUENCE
    //       02 82 01 01 00                     modulus INTEGER tag/len + leading zero
    let header: [u8; 33] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
        0x01, 0x01, 0x00,
    ];
    for i in 0..header.len() {
        tbs[SPKI_OFF + i] = header[i];
    }
    for i in 0..256 {
        tbs[MOD_OFF + i] = modulus[i];
    }
    tbs
}

// Repatch the SEQUENCE / BIT STRING length fields for an exponent of `exp_len` content
// bytes so the framing stays DER-consistent (the base builder hardcodes e=65537).
fn with_rsa_spki_lengths(mut tbs: [u8; 1000], exp_len: u32) -> [u8; 1000] {
    // modulus TLV is fixed at 261 B; exponent TLV is 2 + exp_len; BIT STRING adds the
    // unused-bits octet + SEQUENCE TLV.
    let seq_len: u32 = 261 + 2 + exp_len;
    let bitstr_len: u32 = seq_len + 5;
    // SEQUENCE length `30 82 hi lo` at 124..127, BIT STRING `03 82 hi lo` at 119..122.
    tbs[126] = (seq_len / 256) as u8;
    tbs[127] = (seq_len % 256) as u8;
    tbs[121] = (bitstr_len / 256) as u8;
    tbs[122] = (bitstr_len % 256) as u8;
    tbs
}

#[test]
fn test_verify_rsa_pubkey_in_tbs() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    // publicExponent INTEGER for e=65537: 0x02 | 0x03 | 0x01 0x00 0x01.
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_small_exponent() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = with_rsa_spki_lengths(tbs_with_rsa_spki(rsa_pubkey), 1);
    // e = 3 hits the 1-byte branch: 0x02 | 0x01 | 0x03.
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x01;
    tbs[EXP_OFF + 2] = 0x03;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 3, tbs);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_zero_padded_exponent() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = with_rsa_spki_lengths(tbs_with_rsa_spki(rsa_pubkey), 4);
    // e = 65537 declared with length 4 and a leading zero byte:
    //   0x02 | 0x04 | 0x00 0x01 0x00 0x01
    // Non-canonical DER (DER strips leading zeros), but the big-endian decoder
    // still yields 65537.
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x04;
    tbs[EXP_OFF + 2] = 0x00;
    tbs[EXP_OFF + 3] = 0x01;
    tbs[EXP_OFF + 4] = 0x00;
    tbs[EXP_OFF + 5] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Public key of DSC not found in TBS")]
fn test_verify_rsa_pubkey_in_tbs_fail() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    // Corrupt a few bytes of the modulus so it no longer matches the claimed pubkey.
    tbs[MOD_OFF + 5] = 0;
    tbs[MOD_OFF + 6] = 0;
    tbs[MOD_OFF + 7] = 0;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent INTEGER tag not found after pubkey")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_missing() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    // No INTEGER TLV after the modulus; tbs[EXP_OFF] stays 0x00, not 0x02.
    let tbs = tbs_with_rsa_spki(rsa_pubkey);
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent cannot be greater than 4 bytes")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_length() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    // Length byte of 0x05 exceeds the 4-byte u32 bound.
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x05;
    tbs[EXP_OFF + 2] = 0x00;
    tbs[EXP_OFF + 3] = 0x01;
    tbs[EXP_OFF + 4] = 0x00;
    tbs[EXP_OFF + 5] = 0x00;
    tbs[EXP_OFF + 6] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent of DSC does not match")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_value() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    // Correct tag and length but wrong last value byte (expected 0x01 for e=65537).
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x02;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// Regression (algorithm confusion): a TBS that contains the modulus
// bytes but no rsaEncryption SubjectPublicKeyInfo framing (e.g. an ECDSA cert, or a
// prover-planted window) must be rejected - the anchor OID is absent.
#[test(should_fail_with = "rsaEncryption SPKI not found in TBS")]
fn test_verify_rsa_pubkey_in_tbs_fail_no_spki() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = [0; 1000];
    // Place the raw modulus (and a valid-looking exponent TLV) in the TBS, but with
    // no rsaEncryption AlgorithmIdentifier around it.
    for i in 0..256 {
        tbs[MOD_OFF + i] = rsa_pubkey[i];
    }
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// Regression (leading-zero collapse): a modulus INTEGER whose
// declared length does not match the key size must be rejected, so a shorter
// (zero-collapsed) window cannot pose as a full-size modulus.
#[test(should_fail_with = "Modulus length does not match key size")]
fn test_verify_rsa_pubkey_in_tbs_fail_modulus_length() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    // The modulus INTEGER header sits at SPKI_OFF + 28 (tag 0x02 at index 128).
    // Rewrite its length from 0x82 0x01 0x01 (257) to 0x81 0x80 (128).
    tbs[128] = 0x02;
    tbs[129] = 0x81;
    tbs[130] = 0x80;
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// The SEQUENCE length must equal the modulus + exponent TLVs it wraps.
#[test(should_fail_with = "RSAPublicKey SEQUENCE length mismatch")]
fn test_verify_rsa_pubkey_in_tbs_fail_sequence_length() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    // Shrink the declared SEQUENCE length (266 -> 265) without changing its content.
    tbs[126] = 0x01;
    tbs[127] = 0x09;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// The BIT STRING length must wrap the unused-bits octet + the RSAPublicKey SEQUENCE.
#[test(should_fail_with = "BIT STRING length mismatch")]
fn test_verify_rsa_pubkey_in_tbs_fail_bitstring_length() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki(rsa_pubkey);
    tbs[EXP_OFF] = 0x02;
    tbs[EXP_OFF + 1] = 0x03;
    tbs[EXP_OFF + 2] = 0x01;
    tbs[EXP_OFF + 3] = 0x00;
    tbs[EXP_OFF + 4] = 0x01;
    // Grow the declared BIT STRING length (271 -> 272) while the SEQUENCE stays correct.
    tbs[121] = 0x01;
    tbs[122] = 0x10;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// Offsets inside the TBS built by `tbs_with_rsa_spki_no_null` (the AlgId omits the
// explicit NULL parameters, so everything after it shifts 2 bytes earlier vs the
// NULL-present builder: MOD_OFF 133 -> 131, EXP_OFF 389 -> 387).
global MOD_OFF_NN: u32 = 131;
global EXP_OFF_NN: u32 = 387;

// Build a TBS whose rsaEncryption AlgorithmIdentifier omits the NULL parameters
// (`30 0B 06 09 ...010101` straight into the BIT STRING, no `05 00`). This is
// non-conformant per RFC 5280 but emitted by real HSM-generated certificates in
// the ICAO master list, so the verifier must accept it.
fn tbs_with_rsa_spki_no_null(modulus: [u8; 256]) -> [u8; 1000] {
    let mut tbs = [0 as u8; 1000];
    // 30 82 01 20                          SPKI SEQUENCE (2 bytes shorter: no NULL)
    //   30 0B 06 09 2A8648 86F70D 010101   AlgId: rsaEncryption, NO NULL params
    //   03 82 01 0F 00                     BIT STRING + unused-bits octet
    //     30 82 01 0A                      RSAPublicKey SEQUENCE
    //       02 82 01 01 00                 modulus INTEGER tag/len + leading zero
    let header: [u8; 31] = [
        0x30, 0x82, 0x01, 0x20, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x01, 0x01, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01,
        0x00,
    ];
    for i in 0..header.len() {
        tbs[SPKI_OFF + i] = header[i];
    }
    for i in 0..256 {
        tbs[MOD_OFF_NN + i] = modulus[i];
    }
    tbs
}

// Regression (real-world encoding): a conformant-enough rsaEncryption SPKI that omits
// the NULL parameters must still verify. Mirrors certs #111/#134/#691 of the master list.
#[test]
fn test_verify_rsa_pubkey_in_tbs_no_null_params() {
    let rsa_pubkey: [u8; 256] = sample_modulus();
    let mut tbs: [u8; 1000] = tbs_with_rsa_spki_no_null(rsa_pubkey);
    // publicExponent INTEGER for e=65537: 0x02 | 0x03 | 0x01 0x00 0x01.
    tbs[EXP_OFF_NN] = 0x02;
    tbs[EXP_OFF_NN + 1] = 0x03;
    tbs[EXP_OFF_NN + 2] = 0x01;
    tbs[EXP_OFF_NN + 3] = 0x00;
    tbs[EXP_OFF_NN + 4] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

// Offsets inside the TBS built by `tbs_with_ec_spki` (prime256v1, 32-byte coords).
global EC_X_OFF: u32 = 127; // start of the x coordinate
global EC_Y_OFF: u32 = 159; // start of the y coordinate

fn sample_coord(base: u8) -> [u8; 32] {
    let mut c = [0 as u8; 32];
    for i in 0..32 {
        c[i] = i as u8 + base;
    }
    c
}

// Build a TBS containing a well-formed ecPublicKey SubjectPublicKeyInfo for a
// prime256v1 (P-256) uncompressed point.
fn tbs_with_ec_spki(x: [u8; 32], y: [u8; 32]) -> [u8; 1000] {
    let mut tbs: [u8; 1000] = [0 as u8; 1000];
    // 30 59                                   SPKI SEQUENCE
    //   30 13                                 AlgId SEQUENCE
    //     06 07 2A8648CE3D0201                ecPublicKey OID
    //     06 08 2A8648CE3D030107              prime256v1 named-curve OID
    //   03 42 00 04                           BIT STRING: unused-bits, uncompressed prefix
    let header: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    for i in 0..header.len() {
        tbs[100 + i] = header[i];
    }
    for i in 0..32 {
        tbs[EC_X_OFF + i] = x[i];
        tbs[EC_Y_OFF + i] = y[i];
    }
    tbs
}

#[test]
fn test_verify_ecdsa_pubkey_in_tbs() {
    let ecdsa_pubkey_x: [u8; 32] = sample_coord(2);
    let ecdsa_pubkey_y: [u8; 32] = sample_coord(1);
    let tbs: [u8; 1000] = tbs_with_ec_spki(ecdsa_pubkey_x, ecdsa_pubkey_y);
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Public key x coord not found in TBS")]
fn test_verify_ecdsa_pubkey_in_tbs_fail() {
    let ecdsa_pubkey_x: [u8; 32] = sample_coord(2);
    let ecdsa_pubkey_y: [u8; 32] = sample_coord(1);
    let mut tbs: [u8; 1000] = tbs_with_ec_spki(ecdsa_pubkey_x, ecdsa_pubkey_y);
    // Corrupt a few bytes of the public key x coordinate
    tbs[EC_X_OFF + 5] = 0;
    tbs[EC_X_OFF + 6] = 0;
    tbs[EC_X_OFF + 7] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Public key y coord not found in TBS")]
fn test_verify_ecdsa_pubkey_in_tbs_fail_y_coord() {
    let ecdsa_pubkey_x: [u8; 32] = sample_coord(2);
    let ecdsa_pubkey_y: [u8; 32] = sample_coord(1);
    let mut tbs: [u8; 1000] = tbs_with_ec_spki(ecdsa_pubkey_x, ecdsa_pubkey_y);
    // Corrupt a few bytes of the public key y coordinate
    tbs[EC_Y_OFF + 5] = 0;
    tbs[EC_Y_OFF + 6] = 0;
    tbs[EC_Y_OFF + 7] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

// Regression: a TBS carrying the raw point but no ecPublicKey SubjectPublicKeyInfo
// framing (e.g. a prover-planted window) must be rejected - the anchor OID is absent.
#[test(should_fail_with = "ecPublicKey SPKI not found in TBS")]
fn test_verify_ecdsa_pubkey_in_tbs_fail_no_spki() {
    let ecdsa_pubkey_x: [u8; 32] = sample_coord(2);
    let ecdsa_pubkey_y: [u8; 32] = sample_coord(1);
    let mut tbs: [u8; 1000] = [0; 1000];
    for i in 0..32 {
        tbs[EC_X_OFF + i] = ecdsa_pubkey_x[i];
        tbs[EC_Y_OFF + i] = ecdsa_pubkey_y[i];
    }
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

// Offsets inside the TBS built by `tbs_with_ec_spki_explicit_params`.
global EC_EP_X_OFF: u32 = 125; // start of the x coordinate
global EC_EP_Y_OFF: u32 = 157; // start of the y coordinate

// Build a TBS whose ecPublicKey AlgorithmIdentifier carries explicit ECParameters
// (a SEQUENCE, tag 0x30) instead of a named-curve OID. The real parameters run to
// hundreds of bytes; a short synthetic SEQUENCE is enough to exercise the skip, since
// the walk only consumes the element by its length. This is the common encoding for
// brainpool certificates in the ICAO master list, so it must verify.
fn tbs_with_ec_spki_explicit_params(x: [u8; 32], y: [u8; 32]) -> [u8; 1000] {
    let mut tbs = [0 as u8; 1000];
    // 30 57                                   SPKI SEQUENCE
    //   30 11                                 AlgId SEQUENCE
    //     06 07 2A8648CE3D0201                ecPublicKey OID
    //     30 06 AA BB CC DD EE FF             explicit ECParameters SEQUENCE (stand-in)
    //   03 42 00 04                           BIT STRING: unused-bits, uncompressed prefix
    let header: [u8; 25] = [
        0x30, 0x57, 0x30, 0x11, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x30, 0x06,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x03, 0x42, 0x00, 0x04,
    ];
    for i in 0..header.len() {
        tbs[100 + i] = header[i];
    }
    for i in 0..32 {
        tbs[EC_EP_X_OFF + i] = x[i];
        tbs[EC_EP_Y_OFF + i] = y[i];
    }
    tbs
}

// Regression (real-world encoding): an ecPublicKey SPKI with explicit ECParameters
// must verify. Mirrors the brainpool certs that dominate the master list's EC entries.
#[test]
fn test_verify_ecdsa_pubkey_in_tbs_explicit_params() {
    let ecdsa_pubkey_x: [u8; 32] = sample_coord(2);
    let ecdsa_pubkey_y: [u8; 32] = sample_coord(1);
    let tbs: [u8; 1000] = tbs_with_ec_spki_explicit_params(ecdsa_pubkey_x, ecdsa_pubkey_y);
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}
