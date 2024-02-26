use dep::biguint::BigUint56;
use dep::rsa::{verify_rsa_sha256_pkcs1v15};
use dep::std::hash::sha256;
use dep::utils::{DSCData, CSCACertData, reverse_bytes_array};

/**
* WARNING: the RSA signature verification algorithm used here is making an assumption 
* that is likely not fully secure.
* For now, we continue to use it for performance reason, but we will switch to a fully 
* secure implementation fairly soon.
*/

// Index of where the public key is in the TBS certificate of the DSC
global PUB_KEY_INDEX_IN_TBS_DSC = 261;

/**
* The Document Signing Certificate (DSC) is signed by the 
* Country Signing Certificate Authority (CSCA) of the issuing State.
* So using the CSCA certificate public key and the signature of 
* the TBS certificate of the DSC we can verify the authenticity of the DSC. 
* And since the CSCA certificate is our Trust Anchor, we have completed 
* the necessary chain of trust to verify the authenticity and validity of the passport.
*/
fn verify_dsc_signature(dsc_data: DSCData, csca_cert_data: CSCACertData) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the 
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in PUB_KEY_INDEX_IN_TBS_DSC..PUB_KEY_INDEX_IN_TBS_DSC + dsc_data.pubkey.len() {
        assert(dsc_data.tbs_certificate[i] == dsc_data.pubkey[i - PUB_KEY_INDEX_IN_TBS_DSC]);
    }

    // We assume the bytes are in big endian format so we convert them to little endian
    let sig_biguint = BigUint56::from_bytes(reverse_bytes_array(dsc_data.signature));
    let pubkey_biguint = BigUint56::from_bytes(reverse_bytes_array(csca_cert_data.pubkey));
    let final_e_biguint = BigUint56::from_bytes(reverse_bytes_array(dsc_data.final_e));
    let quotient_biguint = BigUint56::from_bytes(reverse_bytes_array(dsc_data.quotient));

    let msg_hash = sha256(dsc_data.tbs_certificate);

    // Verify the signature of the DSC by the CSCA certificate
    verify_rsa_sha256_pkcs1v15(
        msg_hash,
        sig_biguint,
        pubkey_biguint,
        final_e_biguint,
        quotient_biguint
    )
}


fn main(
    dsc_data: DSCData,
    // The CSCA certificates are public knowledge and 
    // we want to let verifiers use the CSCA certificate
    // that they got from a source they trust to verify the proof
    csca_cert_data: pub CSCACertData,
) {
    verify_dsc_signature(dsc_data, csca_cert_data);
}