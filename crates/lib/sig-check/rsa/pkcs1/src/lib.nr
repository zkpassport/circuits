use dep::rsa::bignum::BigNum;
use dep::rsa::bignum::runtime_bignum::BigNumInstance;
use dep::rsa::bignum::fields::Params2048;
use dep::rsa::bignum::fields::Params4096;
use dep::rsa::types::RSA;

use dep::std::hash::sha256;
use dep::utils::{DSCData, CSCACertData, IDData, reverse_bytes_array};

type BN4096 = BigNum<35, Params4096>;
type BN4096Instance = BigNumInstance<35, Params4096>;
type RSA4096 = RSA<BN4096, BN4096Instance, 512>;

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
pub fn verify_dsc_signature(dsc_data: DSCData, csca_cert_data: CSCACertData) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the 
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in PUB_KEY_INDEX_IN_TBS_DSC..PUB_KEY_INDEX_IN_TBS_DSC + dsc_data.pubkey.len() {
        assert(dsc_data.tbs_certificate[i] == dsc_data.pubkey[i - PUB_KEY_INDEX_IN_TBS_DSC]);
    }

    let msg_hash = sha256(dsc_data.tbs_certificate);

    let pubkey = utils::__from_byte_be_to_fields(csca_cert_data.pubkey);

    let signature: BN4096 = BigNum::from_be_bytes(dsc_data.signature);

    let instance: BN4096Instance = BigNumInstance::new(pubkey, csca_cert_data.redc_param);

    let rsa: RSA4096 = RSA {};
    rsa.verify_sha256_pkcs1v15(instance, msg_hash, signature, csca_cert_data.exponent)
}

type BN2048 = BigNum<18, Params2048>;
type BN2048Instance = BigNumInstance<18, Params2048>;
type RSA2048 = RSA<BN2048, BN2048Instance, 256>;

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature(id_data: IDData, dsc_data: DSCData) -> bool {
    // We assume the bytes are in big endian order
    let signature = BigNum::from_be_bytes(id_data.encrypted_digest);

    let msg_hash = sha256(id_data.e_content);

    let pubkey = utils::__from_byte_be_to_fields(dsc_data.pubkey);

    let redc_param = utils::__from_byte_be_to_fields(dsc_data.redc_param);

    let instance: BN2048Instance = BigNumInstance::new(pubkey, redc_param);

    let rsa: RSA2048 = RSA {};
    // Verify the signature of the passport data by the DSC
    rsa.verify_sha256_pkcs1v15(instance, msg_hash, signature, dsc_data.exponent)
}
