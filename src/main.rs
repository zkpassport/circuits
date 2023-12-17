extern crate noir_rsa_optimised;

use noir_rsa_optimised::{hashmap_to_toml, get_inputs};

fn main() {
    // This is the data that will be signed
    // It is either the DER encoded TBS certificate for checking the signature
    // made by CSCA certificate of the issuing state
    // or the 104 bytes eContent of the passport data
    let data_to_sign = [];
    // This is the actual signature, either the encrypted digest of the passport
    // data or the signature by the CSCA certificate of the DSC DER encoded TBS
    // certificate
    let signature = [];
    // This is the public key, either the public key of the issuing state CSCA
    // certificate that was used to sign the DSC or the public key of the DSC that 
    // was used to sign the passport data
    let pubkey = [];
    let hashmap = get_inputs(data_to_sign.to_vec(), signature.to_vec(), pubkey.to_vec());
    println!("{:?}", hashmap_to_toml(hashmap));   
}
