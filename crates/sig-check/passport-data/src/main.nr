use dep::large_integer::LargeInteger;
use dep::rsa::verify_rsa_sha256_pkcs1v15;
use dep::std::hash::sha256;
use dep::utils::{IDData, DSCData, reverse_bytes_array};

/**
* WARNING: the RSA signature verification algorithm used here is making an assumption 
* that is likely not fully secure.
* For now, we continue to use it for performance reason, but we will switch to a fully 
* secure implementation fairly soon.
*/

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
fn verify_id_signature(id_data: IDData, dsc_data: DSCData) -> bool {
    // We assume the bytes are in big endian format so we convert them to little endian
    let sig_biguint = LargeInteger::from_bytes(reverse_bytes_array(id_data.encrypted_digest));
    let pubkey_biguint = LargeInteger::from_bytes(reverse_bytes_array(dsc_data.pubkey));
    let final_e_biguint = LargeInteger::from_bytes(reverse_bytes_array(id_data.final_e));
    let quotient_biguint = LargeInteger::from_bytes(reverse_bytes_array(id_data.quotient));

    let msg_hash = sha256(id_data.e_content);

    // Verify the signature of the passport data by the DSC
    verify_rsa_sha256_pkcs1v15(
        msg_hash,
        sig_biguint,
        pubkey_biguint,
        final_e_biguint,
        quotient_biguint
    )
}

fn main(id_data: IDData, dsc_data: DSCData) {
    verify_id_signature(id_data, dsc_data);
}
