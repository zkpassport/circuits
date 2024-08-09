use std::env;

extern crate noir_bignum_paramgen;
use noir_bignum_paramgen::bn_runtime_instance_from_string;
extern crate num_bigint;
use num_bigint::BigUint;

fn main() {
    //let args: Vec<String> = env::args().collect();

    //let valid_args = args.len() == 4;
    // This is the public key, either the public key of the issuing state CSCA
    // certificate that was used to sign the DSC or the public key of the DSC that 
    // was used to sign the passport data
    let pubkey = [];

    let big_int_pub_key = BigUint::from_bytes_be(&pubkey);
    let string_pub_key = big_int_pub_key.to_str_radix(16);
    let result = bn_runtime_instance_from_string(string_pub_key, String::from("BigNumInstance"));
    println!("result: {}", result);
}
