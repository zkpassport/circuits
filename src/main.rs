use std::env;

extern crate noir_bignum_paramgen;
use noir_bignum_paramgen::compute_barrett_reduction_parameter;
extern crate num_bigint;
use num_bigint::BigUint;

fn main() {
    //let args: Vec<String> = env::args().collect();

    //let valid_args = args.len() == 4;
    // This is the public key, either the public key of the issuing state CSCA
    // certificate that was used to sign the DSC or the public key of the DSC that 
    // was used to sign the passport data
    let pubkey =  [];

    let big_int_pub_key = BigUint::from_bytes_be(&pubkey);
    let result = compute_barrett_reduction_parameter(&big_int_pub_key);
    let result_bytes = result.to_bytes_be();
    println!("redc_param: {:?}", result_bytes);
}
