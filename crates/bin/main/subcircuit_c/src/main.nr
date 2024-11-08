/*
############################################################
# Circuit C
############################################################
# Verifies the integrity of the ePassport data
############################################################

# Inputs/Outputs
############################################################
current_date
comm_in                 `assert comm_in == H(salt, country, signed_attr, sod_sig)`
salt
country
signed_attr
signed_attr_size
sod_sig
dg1
econtent
private_nullifier       `assert private_nullifier == H(dg1, sod_sig)`
comm_out                `H(salt, dg1, private_nullifier)`

# Checks
############################################################
- Check that passport expiry date <= current date
- Checks that the dg1 hash is present in econtent
- Checks that the hash of econtent is present in signed_attr
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

fn hash_salt_dg1_private_nullifier<let N: u32>(salt: Field, dg1: [u8; N], private_nullifier: Field) -> Field {
    let mut result: [Field; N+2] = [0; N+2];
    result[0] = salt as Field;
    for i in 0..N {
        result[1+i] = dg1[i] as Field;
    }
    result[1+N] = private_nullifier;
    pedersen_hash(result)
}

fn calculate_private_nullifier<let DG1: u32, let SIG: u32>(dg1: [u8; DG1], sod_sig: [u8; SIG]) -> Field {
    let mut result: [Field; DG1+SIG+2] = [0; DG1+SIG+2];
    for i in 0..DG1 {
        result[i] = dg1[i] as Field;
    }
    for i in 0..SIG {
        result[DG1+i] = sod_sig[i] as Field;
    }
    pedersen_hash(result)
}

#[recursive]
fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt: Field,

    country: str<3>,
    signed_attr: [u8; 200],
    signed_attr_size: Field,
    sod_sig: [u8; 256],
    dg1: [u8; 93],
    econtent: [u8; 700],
    private_nullifier: Field,

    comm_out: pub Field,
) {
    assert(comm_in == hash_salt_country_signed_attr_sod_sig(salt, country, signed_attr, signed_attr_size, sod_sig));
    // println(f"comm_in: {comm_in}");

    assert(private_nullifier == calculate_private_nullifier(dg1, sod_sig));
    // println(f"private_nullifier: {private_nullifier}");

    assert(comm_out == hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier));
    // println(f"comm_out: {comm_out}");
}

#[test]
fn test_main() {
    let current_date: str<8> = "20241101";
    let salt: Field = 42;
    let country: str<3> = "AUS";
    let signed_attr: [u8; 200] = [0; 200];
    let signed_attr_size: Field = 200;
    let sod_sig: [u8; 256] = [0; 256];
    let dg1: [u8; 95] = [0; 95];
    let econtent: [u8; 700] = [0; 700];
    let private_nullifier: Field = calculate_private_nullifier(dg1, sod_sig);

    let comm_in: Field = hash_salt_country_signed_attr_sod_sig(salt, country, signed_attr, signed_attr_size, sod_sig);
    let comm_out: Field = hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier);

    main(
        current_date,
        comm_in,
        salt,
        country,
        signed_attr,
        signed_attr_size,
        sod_sig,
        dg1,
        econtent,
        private_nullifier,
        comm_out,
    );
}
