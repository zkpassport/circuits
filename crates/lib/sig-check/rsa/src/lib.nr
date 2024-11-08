use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::{verify_sha256_pkcs1v15, verify_sha256_pss};

use std::hash::sha256;
use utils::{DSCData, IDData, CSCData, get_array_slice_constant};

// It felt tidier to use a BYTES generic instead of BIT here.
fn verify_signature<let SIG_BYTES: u32, let IS_PSS: u32>(
    msg_hash: [u8; 32],
    pubkey_bytes: [u8; SIG_BYTES],
    sig_bytes: [u8; SIG_BYTES],
    redc_param_bytes: [u8; SIG_BYTES + 1],
    exponent: u32,
) -> bool {
    assert(
        (SIG_BYTES == 512) | (SIG_BYTES == 384) | (SIG_BYTES == 256) | (SIG_BYTES == 128),
        "Only modulus of bit size 1024, 2048, 3072 and 4096 are supported",
    );

    let pubkey = utils::from_byte_be_to_fields::<SIG_BYTES, (SIG_BYTES + 14) / 15>(pubkey_bytes);
    let redc_param = utils::from_byte_be_to_fields::<SIG_BYTES + 1, _>(redc_param_bytes);
    let params = BigNumParams::new(false, pubkey, redc_param);

    let signature = RuntimeBigNum::from_be_bytes(params, sig_bytes);

    if (IS_PSS == 1) {
        verify_sha256_pss::<_, SIG_BYTES * 8>(msg_hash, signature, SIG_BYTES * 8)
    } else {
        verify_sha256_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
    }
}

/**
* The Document Signing Certificate (DSC) is signed by the 
* Country Signing Certificate Authority (CSCA) of the issuing State.
* So using the CSCA certificate public key and the signature of 
* the TBS certificate of the DSC we can verify the authenticity of the DSC. 
* And since the CSCA certificate is our Trust Anchor, we have completed 
* the necessary chain of trust to verify the authenticity and validity of the passport.
*/
pub fn verify_dsc_signature<let SIG_BYTES: u32, let IS_PSS: u32>(
    dsc_data: DSCData,
    csc_data: CSCData,
) -> bool {
    // Check that the public key of the DSC is the same as the one in the TBS certificate.
    // And since the TBS certificate is the data signed by the private key of the CSCA certificate
    // we can make sure the DSC, which signed the data of the passport, has been signed by the
    // root certificate of the issuing State (i.e. CSCA certificate) by verifying the signature below
    for i in 0..dsc_data.pubkey.len() {
        if (i < dsc_data.pubkey_size) {
            assert(dsc_data.tbs_certificate[i + dsc_data.pubkey_index] == dsc_data.pubkey[i]);
        }
    }

    let msg_hash = sha256::sha256_var(
        dsc_data.tbs_certificate,
        dsc_data.tbs_certificate_size as u64,
    );

    let modulus: [u8; SIG_BYTES] = get_array_slice_constant(csc_data.pubkey);
    let signature: [u8; SIG_BYTES] = get_array_slice_constant(dsc_data.signature);
    let modulus_redc_param: [u8; SIG_BYTES + 1] =
        get_array_slice_constant(csc_data.pubkey_redc_param);
    verify_signature::<_, IS_PSS>(
        msg_hash,
        modulus,
        signature,
        modulus_redc_param,
        csc_data.exponent,
    )
}

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
pub fn verify_id_signature<let SIG_BYTES: u32, let IS_PSS: u32>(
    id_data: IDData,
    dsc_data: DSCData,
) -> bool {
    let msg_hash = sha256::sha256_var(
        id_data.signed_attributes,
        id_data.signed_attributes_size as u64,
    );

    let modulus: [u8; SIG_BYTES] = get_array_slice_constant(dsc_data.pubkey);
    let signature: [u8; SIG_BYTES] = get_array_slice_constant(id_data.sod_signature);
    let modulus_redc_param: [u8; SIG_BYTES + 1] =
        get_array_slice_constant(dsc_data.pubkey_redc_param);
    verify_signature::<_, IS_PSS>(
        msg_hash,
        modulus,
        signature,
        modulus_redc_param,
        dsc_data.exponent,
    )
}
