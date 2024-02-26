use dep::biguint::BigUint56;
use dep::rsa::{verify_rsa_sha256_pkcs1v15};
use dep::std::hash::sha256;
use dep::utils::{PassportData, DSCData, reverse_bytes_array};

/**
* WARNING: the RSA signature verification algorithm used here is making an assumption 
* that is likely not fully secure.
* For now, we continue to use it for performance reason, but we will switch to a fully 
* secure implementation fairly soon.
*/


/**
* The Document Signing Certificate (DSC) signs the passport data, which is the hash of the
* all the data groups present in the passport. So using the DSC public key and this signature
* we can verify the authenticity of the passport data.
*/
fn verify_passport_signature(passport_data: PassportData, dsc_data: DSCData) -> bool {
    // We assume the bytes are in big endian format so we convert them to little endian
    let sig_biguint = BigUint56::from_bytes(reverse_bytes_array(passport_data.encrypted_digest));
    let pubkey_biguint = BigUint56::from_bytes(reverse_bytes_array(dsc_data.pubkey));
    let final_e_biguint = BigUint56::from_bytes(reverse_bytes_array(passport_data.final_e));
    let quotient_biguint = BigUint56::from_bytes(reverse_bytes_array(passport_data.quotient));

    let msg_hash = sha256(passport_data.e_content);

    // Verify the signature of the passport data by the DSC
    verify_rsa_sha256_pkcs1v15(
        msg_hash,
        sig_biguint,
        pubkey_biguint,
        final_e_biguint,
        quotient_biguint
    )
}

fn main(
    passport_data: PassportData,
    dsc_data: DSCData,
) {
    verify_passport_signature(passport_data, dsc_data);
}
