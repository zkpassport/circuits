use super::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};

#[test]
fn test_verify_rsa_pubkey_in_tbs() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // Immediately after the modulus (which ends at index 355), place the DER-encoded
    // publicExponent INTEGER for e=65537: 0x02 | 0x03 | 0x01 0x00 0x01.
    tbs[356] = 0x02;
    tbs[357] = 0x03;
    tbs[358] = 0x01;
    tbs[359] = 0x00;
    tbs[360] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_small_exponent() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // e = 3 hits the 1-byte branch: 0x02 | 0x01 | 0x03 immediately after the modulus.
    tbs[356] = 0x02;
    tbs[357] = 0x01;
    tbs[358] = 0x03;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 3, tbs);
}

#[test]
fn test_verify_rsa_pubkey_in_tbs_zero_padded_exponent() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // e = 65537 declared with length 4 and a leading zero byte:
    //   0x02 | 0x04 | 0x00 0x01 0x00 0x01
    // This is a non-canonical DER encoding (DER strips leading zeros), but the
    // big-endian decoder still yields 65537.
    tbs[356] = 0x02;
    tbs[357] = 0x04;
    tbs[358] = 0x00;
    tbs[359] = 0x01;
    tbs[360] = 0x00;
    tbs[361] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Index out of bounds")]
fn test_verify_rsa_pubkey_in_tbs_fail() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    tbs[356] = 0x02;
    tbs[357] = 0x03;
    tbs[358] = 0x01;
    tbs[359] = 0x00;
    tbs[360] = 0x01;
    // Corrupt a few bytes of the public key
    tbs[105] = 0;
    tbs[106] = 0;
    tbs[107] = 0;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent INTEGER tag not found after pubkey")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_missing() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // No INTEGER TLV after the modulus; tbs[356] is 0x00, not 0x02.
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent cannot be greater than 4 bytes")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_length() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // Length byte of 0x05 exceeds the 4-byte u32 bound.
    tbs[356] = 0x02;
    tbs[357] = 0x05;
    tbs[358] = 0x00;
    tbs[359] = 0x01;
    tbs[360] = 0x00;
    tbs[361] = 0x00;
    tbs[362] = 0x01;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test(should_fail_with = "Exponent of DSC does not match")]
fn test_verify_rsa_pubkey_in_tbs_fail_exponent_value() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut rsa_pubkey: [u8; 256] = [0; 256];
    for i in 0..rsa_pubkey.len() {
        rsa_pubkey[i] = i as u8;
    }
    for i in 0..rsa_pubkey.len() {
        tbs[i + 100] = rsa_pubkey[i];
    }
    // Correct tag and length but wrong last value byte (expected 0x01 for e=65537).
    tbs[356] = 0x02;
    tbs[357] = 0x03;
    tbs[358] = 0x01;
    tbs[359] = 0x00;
    tbs[360] = 0x02;
    verify_rsa_pubkey_in_tbs(rsa_pubkey, 65537, tbs);
}

#[test]
fn test_verify_ecdsa_pubkey_in_tbs() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Index out of bounds")]
fn test_verify_ecdsa_pubkey_in_tbs_fail() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    // Corrupt a few bytes of the public key x coordinate
    tbs[105] = 0;
    tbs[106] = 0;
    tbs[107] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}

#[test(should_fail_with = "Public key y coord not found in TBS")]
fn test_verify_ecdsa_pubkey_in_tbs_fail_y_coord() {
    let mut tbs: [u8; 1000] = [0; 1000];
    let mut ecdsa_pubkey_x: [u8; 32] = [0; 32];
    let mut ecdsa_pubkey_y: [u8; 32] = [0; 32];
    for i in 0..ecdsa_pubkey_x.len() {
        ecdsa_pubkey_x[i] = i as u8 + 2;
    }
    for i in 0..ecdsa_pubkey_y.len() {
        ecdsa_pubkey_y[i] = i as u8 + 1;
    }
    for i in 0..ecdsa_pubkey_x.len() {
        tbs[i + 100] = ecdsa_pubkey_x[i];
        tbs[i + 100 + 32] = ecdsa_pubkey_y[i];
    }
    // Corrupt a few bytes of the public key y coordinate
    tbs[100 + 5 + 32] = 0;
    tbs[100 + 6 + 32] = 0;
    tbs[100 + 7 + 32] = 0;
    verify_ecdsa_pubkey_in_tbs(ecdsa_pubkey_x, ecdsa_pubkey_y, tbs);
}
