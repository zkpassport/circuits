use dep::rsa::bignum::BigNum;
use dep::rsa::bignum::runtime_bignum::BigNumInstance;
use dep::rsa::bignum::fields::Params2048;
use dep::rsa::RSA;

use dep::std::hash::sha256;
use dep::utils::{IDData, DSCData, reverse_bytes_array};

type BN2048 = BigNum<18, Params2048>;
type BNInstance = BigNumInstance<18, Params2048>;
type RSA2048 = RSA<BN2048, BNInstance, 256>;

/**
* The Document Signing Certificate (DSC) signs the ID data, which is the hash of the
* all the data groups present in the ID. So using the DSC public key and this signature
* we can verify the authenticity of the ID data.
*/
fn verify_id_signature(id_data: IDData, dsc_data: DSCData) -> bool {
    // We assume the bytes are in big endian order
    let signature = BigNum::from_byte_be(id_data.encrypted_digest);

    let msg_hash = sha256(id_data.e_content);

    let pubkey_bignum: BN2048 = BigNum::from_byte_be(dsc_data.pubkey);
    let pubkey = pubkey_bignum.get();

    let instance: BNInstance = BigNumInstance::new(pubkey.as_array(), dsc_data.redc_param);

    let rsa: RSA2048 = RSA {};
    // Verify the signature of the passport data by the DSC
    rsa.verify_sha256_pkcs1v15(instance, msg_hash, signature)
}

fn main(id_data: IDData, dsc_data: DSCData) {
    verify_id_signature(id_data, dsc_data);
}
