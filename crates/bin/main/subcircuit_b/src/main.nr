/*
############################################################
# Circuit B
############################################################
# Verifies the DSC signed the ePassport
############################################################

# Inputs/Outputs
############################################################
comm_in         `assert comm_in == H(salt, country, dsc_pubkey)`
salt
country
signed_attr     `verify_sig(signed_attr, sod_sig, dsc_pubkey)`
signed_attr_size
dsc_pubkey
sod_sig
comm_out        `H(salt, country, signed_attr, sod_sig)`

# Checks
############################################################
- Check that sod_sig is the signature of dsc_pubkey over signed_attr
*/

use std::hash::pedersen_hash;

fn hash_salt_country_signed_attr_sod_sig<let SA: u32, let SIG: u32>(salt: Field, country: str<3>, signed_attr: [u8; SA], signed_attr_size: Field, sod_sig: [u8; SIG]) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; SA+SIG+5] = [0; SA+SIG+5];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..SA {
        result[4+i] = signed_attr[i] as Field;
    }
    result[4+SA] = signed_attr_size;
    for i in 0..SIG {
        result[4+SA+1+i] = sod_sig[i] as Field;
    }
    pedersen_hash(result)
}

fn hash_salt_country_pubkey<let N: u32>(salt: Field, country: str<3>, pubkey: [u8; N]) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N+4] = [0; N+4];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..N {
        result[i+4] = pubkey[i] as Field;
    }
    pedersen_hash(result)
}

#[recursive]
fn main(
    comm_in: pub Field,
    salt: Field,

    country: str<3>,
    signed_attr: [u8; 200],
    signed_attr_size: Field,
    dsc_pubkey: [u8; 256],
    sod_sig: [u8; 256],

    comm_out: pub Field
) {
    assert(comm_in == hash_salt_country_pubkey(salt, country, dsc_pubkey));
    // println(f"comm_in: {comm_in}");

    assert(comm_out == hash_salt_country_signed_attr_sod_sig(salt, country, signed_attr, signed_attr_size, sod_sig));
    // println(f"comm_out: {comm_out}");
}

#[test]
fn test_main() {
    let salt: Field = 42;
    let country: str<3> = "AUS";
    let signed_attr: [u8; 200] = [0; 200];
    let signed_attr_size: Field = 74;
    let dsc_pubkey: [u8; 256] = [0; 256];
    let sod_sig: [u8; 256] = [0; 256];

    let comm_in: Field = hash_salt_country_pubkey(salt, country, dsc_pubkey);
    let comm_out: Field = hash_salt_country_signed_attr_sod_sig(salt, country, signed_attr, signed_attr_size, sod_sig);

    main(
        comm_in,
        salt,
        country,
        signed_attr,
        signed_attr_size,
        dsc_pubkey,
        sod_sig,
        comm_out,
    );
}
