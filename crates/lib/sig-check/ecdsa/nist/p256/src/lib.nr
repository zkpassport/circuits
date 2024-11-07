use dep::std::hash::sha256;
use dep::utils::{DSCData, IDData};
use dep::std::ecdsa_secp256r1;

/**
* The Document Signing Certificate (DSC) is signed by the 
* Country Signing Certificate Authority (CSCA) of the issuing State.
* So using the CSCA certificate public key and the signature of 
* the TBS certificate of the DSC we can verify the authenticity of the DSC. 
* And since the CSCA certificate is our Trust Anchor, we have completed 
* the necessary chain of trust to verify the authenticity and validity of the passport.
*/
pub fn verify_dsc_signature(dsc_data: DSCData, ecdsa_p256_info: ECDSAP256Info) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the 
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..dsc_data.pubkey_size {
        assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index] == dsc_data.pubkey[i]);
    }

    let msg_hash = sha256(dsc_data.tbs_certificate);

    ecdsa_secp256r1::verify_signature(ecdsa_p256_info.pubkey_x, ecdsa_p256_info.pubkey_y, ecdsa_p256_info.signature, msg_hash)
}

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature(id_data: IDData, ecdsa_p256_info: ECDSAP256Info) -> bool {
    let msg_hash = sha256(id_data.signed_attributes);

    // Verify the signature of the passport data by the DSC
    ecdsa_secp256r1::verify_signature(ecdsa_p256_info.pubkey_x, ecdsa_p256_info.pubkey_y, ecdsa_p256_info.signature, msg_hash)
}
