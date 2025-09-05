/// Check that an RSA public key exists in a certificate TBS
pub fn verify_rsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    // Similar comments to `verify_ecdsa_pubkey_in_tbs` below.
    let pubkey_offset = utils::find_subarray_index(pubkey, tbs);
    for i in 0..PUBKEY_SIZE {
        assert(tbs[i + pubkey_offset] == pubkey[i], "Public key of DSC not found in TBS");
    }
}

/// Check that an ECDSA public key x and y coord exists in a certificate TBS
pub fn verify_ecdsa_pubkey_in_tbs<let PUBKEY_SIZE: u32, let TBS_SIZE: u32>(
    pubkey_x: [u8; PUBKEY_SIZE],
    pubkey_y: [u8; PUBKEY_SIZE],
    tbs: [u8; TBS_SIZE],
) {
    // This assumes there's no possibility for the x-coordinate to match any other substring in the tbs-certificate
    // (i.e. no colliding bytes at some other position in `tbs`), because `find_subarray_index` does not necessarily guarantee that the returned value is the _first_ occurrence (see comments in that function).
    // That seems like a reasonable assumption, but I don't know the contents of a tbs-certificate well enough to validate that assumption.
    // Danger: see concerns in `find_subarray_index`.
    // Danger: this function does not handle a return value of `HAYSTACK_SIZE` meaning "not found": it will blindly use that value as an offset 
    // for the y-coord check below. Now that might fail just because it's unlikely that there will be a matching y-coordinate at the `HAYSTACK_SIZE`
    // offset, but it's difficult to validate that the circuit would indeed always fail in such a case.
    let pubkey_offset = utils::find_subarray_index(pubkey_x, tbs);
    for i in 0..PUBKEY_SIZE {
        // We only need to check that the y coord is found after the x coord, since
        // find_substring_index() already guarantees that the x coord exists in the TBS
        assert(
            tbs[i + pubkey_offset + PUBKEY_SIZE] == pubkey_y[i], // hopefully the compiler is good enough to remove the redundant `pubkey_offset + PUBKEY_SIZE` operation each loop.
            "Public key y coord not found in TBS",
        );
    }
}
