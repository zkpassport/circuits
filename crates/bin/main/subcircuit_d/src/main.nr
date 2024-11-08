/*
############################################################
# Circuit D
############################################################
# Generates a scoped nullifier that is scoped by service
# Allows selective disclosure of dg1 via a reveal bitmask
############################################################

# Inputs/Outputs
############################################################
comm_in             `assert comm_in == H(salt, dg1, private_nullifier)`
salt
dg1
private_nullifier
dg1_mask
dg1_reveal
service_scope       `H(<domain_name>)`
service_subscope    `H(<purpose>)` (Service-specific subscope)
scoped_nullifier    `H(private_nullifier, service_scope, service_subscope)`

# Checks
############################################################
- Checks that dg1_reveal is the correct reveal of dg1 for the given dg1_mask
- Constrains scoped_nullifier to be `H(private_nullifier, service_scope, service_subscope)`
*/

use std::hash::pedersen_hash;

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

fn calculate_scoped_nullifier(private_nullifier: Field, service_scope: Field, service_subscope: Field) -> Field {
    pedersen_hash([private_nullifier, service_scope, service_subscope])
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

#[recursive]
fn main(
    comm_in: pub Field,
    salt: Field,
    dg1: [u8; 95],
    private_nullifier: Field,
    dg1_mask: pub [u8; 95],
    dg1_reveal: pub [u8; 95],
    service_scope: pub Field,
    service_subscope: pub Field,
    scoped_nullifier: pub Field
) {
    assert(comm_in == hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier));
    // println(f"comm_in: {comm_in}");
    assert(scoped_nullifier == calculate_scoped_nullifier(private_nullifier, service_scope, service_subscope));
    // println(f"scoped_nullifier: {scoped_nullifier}");
}

#[test]
fn test_main() {
    let sod_sig: [u8; 256] = [0; 256];

    let salt: Field = 42;
    let dg1: [u8; 95] = [1,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let private_nullifier: Field = calculate_private_nullifier(dg1, sod_sig);

    let dg1_mask: [u8; 95] = [1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let dg1_reveal: [u8; 95] = [1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let service_scope: Field = 4242;
    let service_subscope: Field = 0;
    let scoped_nullifier: Field = calculate_scoped_nullifier(private_nullifier, service_scope, service_subscope);

    let comm_in: Field = hash_salt_dg1_private_nullifier(salt, dg1, private_nullifier);

    main(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        dg1_mask,
        dg1_reveal,
        service_scope,
        service_subscope,
        scoped_nullifier,
    );
}
