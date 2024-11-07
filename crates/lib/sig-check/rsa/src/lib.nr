use dep::bignum::{params::BigNumParams, RuntimeBigNum};
use dep::rsa::rsa::verify_sha256_pkcs1v15; //, rsa::verify_sha256_pss, types::RBN2048, types::RBN4096};

use dep::std::hash::sha256;
use dep::utils::{DSCData, IDData, RSA2048Info, RSA4096Info};

// Index of where the public key is in the TBS certificate of the DSC
//global PUB_KEY_INDEX_IN_TBS_DSC = 261;

// It felt tidier to use a BYTES generic instead of BIT here.
fn verify_signature<let SIG_BYTES: u32, let IS_PSS: u32>(
    msg_hash: [u8; 32],
    pubkey_bytes: [u8; SIG_BYTES],
    sig_bytes: [u8; SIG_BYTES],
    redc_param_bytes: [u8; SIG_BYTES + 1],
    exponent: u32,
) -> bool {
    assert(
        (SIG_BYTES == 512) | (SIG_BYTES == 256),
        "Only modulus of bit size 2048 and 4096 are supported",
    );

    // It's probably not secure to call an unconstrained function like this; since a malicious prover could provide some value `pubkey` unrelated to `pubkey_bytes`. You might want to call the _constrained_ version of this function.
    let pubkey = utils::from_byte_be_to_fields(pubkey_bytes);
    let redc_param = utils::from_byte_be_to_fields(redc_param_bytes);
    let params = BigNumParams::new(false, pubkey, redc_param);

    let signature = RuntimeBigNum::from_be_bytes(params, sig_bytes);

    // if (IS_PSS == 1) {
    // verify_sha256_pss::<(MOD_BITS + 119) / 120, MOD_BITS>(msg_hash, signature, MOD_BITS)
    // } else {
    verify_sha256_pkcs1v15(msg_hash, signature, exponent)
    // }
}

/**
* The Document Signing Certificate (DSC) is signed by the 
* Country Signing Certificate Authority (CSCA) of the issuing State.
* So using the CSCA certificate public key and the signature of 
* the TBS certificate of the DSC we can verify the authenticity of the DSC. 
* And since the CSCA certificate is our Trust Anchor, we have completed 
* the necessary chain of trust to verify the authenticity and validity of the passport.
*/
pub fn verify_dsc_signature_4096<let IS_PSS: u32>(
    dsc_data: DSCData,
    rsa_4096_info: RSA4096Info,
) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..rsa_4096_info.modulus.len() {
        assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index] == rsa_4096_info.modulus[i]);
    }

    let msg_hash = sha256(dsc_data.tbs_certificate);

    verify_signature::<_, IS_PSS>(
        msg_hash,
        rsa_4096_info.modulus,
        rsa_4096_info.signature,
        rsa_4096_info.modulus_redc_param,
        rsa_4096_info.exponent,
    )
}

pub fn verify_dsc_signature_2048<let IS_PSS: u32>(
    dsc_data: DSCData,
    rsa_2048_info: RSA2048Info,
) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..rsa_2048_info.modulus.len() {
        assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index] == rsa_2048_info.modulus[i]);
    }

    let msg_hash = sha256(dsc_data.tbs_certificate);

    verify_signature::<_, IS_PSS>(
        msg_hash,
        rsa_2048_info.modulus,
        rsa_2048_info.signature,
        rsa_2048_info.modulus_redc_param,
        rsa_2048_info.exponent,
    )
}

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature_4096<let IS_PSS: u32>(
    id_data: IDData,
    rsa_4096_info: RSA4096Info,
) -> bool {
    let msg_hash = sha256(id_data.signed_attributes);

    verify_signature::<_, IS_PSS>(
        msg_hash,
        rsa_4096_info.modulus,
        rsa_4096_info.signature,
        rsa_4096_info.modulus_redc_param,
        rsa_4096_info.exponent,
    )
}

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature_2048<let IS_PSS: u32>(
    id_data: IDData,
    rsa_2048_info: RSA2048Info,
) -> bool {
    let msg_hash = sha256(id_data.signed_attributes);

    verify_signature::<_, IS_PSS>(
        msg_hash,
        rsa_2048_info.modulus,
        rsa_2048_info.signature,
        rsa_2048_info.modulus_redc_param,
        rsa_2048_info.exponent,
    )
}
