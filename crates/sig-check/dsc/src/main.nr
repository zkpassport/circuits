use dep::rsa::bignum::BigNum;
use dep::rsa::bignum::runtime_bignum::BigNumInstance;
use dep::rsa::bignum::fields::Params4096;
use dep::rsa::RSA;

use dep::std::hash::sha256;
use dep::utils::{DSCData, CSCACertData, reverse_bytes_array};

type BN4096 = BigNum<35, Params4096>;
type BNInstance = BigNumInstance<35, Params4096>;
type RSA4096 = RSA<BN4096, BNInstance, 512>;

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

    let msg_hash = sha256(dsc_data.tbs_certificate);

    let pubkey_bignum: BN4096 = BigNum::from_byte_be(csca_cert_data.pubkey);
    let pubkey = pubkey_bignum.get();

    let signature = BigNum::from_byte_be(dsc_data.signature);

    let instance: BNInstance = BigNumInstance::new(pubkey.as_array(), csca_cert_data.redc_param);

    let rsa: RSA4096 = RSA {};
    // Verify the signature of the DSC by the CSCA certificate
    rsa.verify_sha256_pkcs1v15(instance, msg_hash, signature)
}

fn main(
    dsc_data: DSCData,
    // The CSCA certificates are public knowledge and 
    // we want to let verifiers use the CSCA certificate
    // that they got from a source they trust to verify the proof
    csca_cert_data: pub CSCACertData
) {
    verify_dsc_signature(dsc_data, csca_cert_data);
}
