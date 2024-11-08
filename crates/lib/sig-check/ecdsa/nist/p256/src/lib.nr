use std::hash::sha256;
use utils::{DSCData, IDData, CSCData};
use std::ecdsa_secp256r1;
use utils::get_array_slice;

/**
* The Document Signing Certificate (DSC) is signed by the 
* Country Signing Certificate Authority (CSCA) of the issuing State.
* So using the CSCA certificate public key and the signature of 
* the TBS certificate of the DSC we can verify the authenticity of the DSC. 
* And since the CSCA certificate is our Trust Anchor, we have completed 
* the necessary chain of trust to verify the authenticity and validity of the passport.
*/
pub fn verify_dsc_signature(dsc_data: DSCData, csc_data: CSCData) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..dsc_data.pubkey_size {
        if (i < dsc_data.pubkey_size / 2) {
            assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index] == dsc_data.pubkey[i]);
        } else {
            // There is two bytes of padding in between the x and y coordinates of the public key
            // So we skip it (hence the +2)
            assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index + 2] == dsc_data.pubkey[i]);
        }
    }

    let msg_hash = sha256::sha256_var(
        dsc_data.tbs_certificate,
        dsc_data.tbs_certificate_size as u64,
    );

    let pubkey_x: [u8; 32] = get_array_slice(csc_data.pubkey, 0, 32);
    let pubkey_y: [u8; 32] = get_array_slice(csc_data.pubkey, 32, 64);
    let signature: [u8; 64] = get_array_slice(dsc_data.signature, 0, 64);
    ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash)
}

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature(id_data: IDData, dsc_data: DSCData) -> bool {
    let msg_hash = sha256::sha256_var(
        id_data.signed_attributes,
        id_data.signed_attributes_size as u64,
    );

    let pubkey_x: [u8; 32] = get_array_slice(dsc_data.pubkey, 0, 32);
    let pubkey_y: [u8; 32] = get_array_slice(dsc_data.pubkey, 32, 64);
    let signature: [u8; 64] = get_array_slice(id_data.sod_signature, 0, 64);
    // Verify the signature of the passport data by the DSC
    ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, signature, msg_hash)
}
