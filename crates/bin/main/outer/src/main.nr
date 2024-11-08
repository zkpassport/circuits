/*
############################################################
# Outer Circuit
############################################################
# Wraps 4 inner proofs (from circuits A, B, C and D)
############################################################

# Inputs/Outputs
############################################################

# Outstanding Questions
############################################################
- Outer circuit interface: single multiparam commitment output, for uniform interface? e.g. `H(dg1_bitmask, dg1_reveal, service_scope, nullifier)`
Can be verified outside of circuit proof with correct pre-image
*/

use std::verify_proof;

fn prepare_proof_c_inputs<let DATE_LEN: u32>(
    current_date: str<DATE_LEN>,
    f1: Field,
    f2: Field,
) -> [Field; DATE_LEN + 2] {
    let date_bytes: [u8; DATE_LEN] = current_date.as_bytes();
    let mut result: [Field; 2 + DATE_LEN] = [0; 2 + DATE_LEN];
    for i in 0..DATE_LEN {
        result[i] = date_bytes[i] as Field;
    }
    result[DATE_LEN] = f1;
    result[DATE_LEN + 1] = f2;
    result
}

fn prepare_proof_d_inputs<let DG1: u32>(
    comm_in: Field,
    dg1_mask: [u8; DG1],
    dg1_reveal: [u8; DG1],
    service_scope: Field,
    service_subscope: Field,
    scoped_nullifier: Field,
) -> [Field; 1 + DG1 + DG1 + 3] {
    let mut result: [Field; 1 + DG1 + DG1 + 3] = [0; 1 + DG1 + DG1 + 3];
    result[0] = comm_in;
    for i in 0..DG1 {
        result[1 + i] = dg1_mask[i] as Field;
    }
    for i in 0..DG1 {
        result[1 + DG1 + i] = dg1_reveal[i] as Field;
    }
    result[1 + DG1 + DG1] = service_scope;
    result[1 + DG1 + DG1 + 1] = service_subscope;
    result[1 + DG1 + DG1 + 2] = scoped_nullifier;
    result
}

struct SubCircuitA {
    vkey: [Field; 128],
    proof: [Field; 439],
    key_hash: Field,
    public_inputs: [Field; 1],
    // Hash path for circuit A key hash in the sub-circuit merkle tree
    // Allows for up to 4,096 leaves
    tree_hash_path: [Field; 12],
    // Index of circuit A key hash in the sub-circuit merkle tree
    tree_index: Field,
}
struct SubCircuitB {
    vkey: [Field; 128],
    proof: [Field; 439],
    public_inputs: [Field; 2],
    key_hash: Field,
    // Hash path for circuit B key hash in the sub-circuit merkle tree
    tree_hash_path: [Field; 12],
    // Index of circuit B key hash in the sub-circuit merkle tree
    tree_index: Field,
}
struct SubCircuitC {
    vkey: [Field; 128],
    proof: [Field; 439],
    public_inputs: [Field; 2],
    key_hash: Field,
    // Hash path for circuit C key hash in the sub-circuit merkle tree
    tree_hash_path: [Field; 12],
    // Index of circuit C key hash in the sub-circuit merkle tree
    tree_index: Field,
}
struct SubCircuitD {
    vkey: [Field; 128],
    proof: [Field; 439],
    public_inputs: [Field; 1],
    key_hash: Field,
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    tree_index: Field,
}

fn verify_subproofs(
    // Root of the sub-circuit merkle tree
    circuit_registry_root: Field,
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Current date as a string, e.g. 20241103
    current_date: str<8>,
    // A mask representing which bytes of DG1 to reveal
    dg1_mask: [u8; 95],
    // The revealed bytes of DG1
    dg1_reveal: [u8; 95],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    proof_a: SubCircuitA,
    proof_b: SubCircuitB,
    proof_c: SubCircuitC,
    proof_d: SubCircuitD,
) {
    // Verify that sub-circuit a, b, c, and d vkey hashes exist in the circuit tree
    let root = std::merkle::compute_merkle_root(
        proof_a.key_hash,
        proof_a.tree_index,
        proof_a.tree_hash_path,
    );
    assert(root == circuit_registry_root);
    let root = std::merkle::compute_merkle_root(
        proof_b.key_hash,
        proof_b.tree_index,
        proof_b.tree_hash_path,
    );
    assert(root == circuit_registry_root);
    let root = std::merkle::compute_merkle_root(
        proof_c.key_hash,
        proof_c.tree_index,
        proof_c.tree_hash_path,
    );
    assert(root == circuit_registry_root);
    let root = std::merkle::compute_merkle_root(
        proof_d.key_hash,
        proof_d.tree_index,
        proof_d.tree_hash_path,
    );
    assert(root == circuit_registry_root);

    verify_proof(
        proof_a.vkey,
        proof_a.proof,
        [
            certificate_registry_root,
            proof_a.public_inputs[0], // comm_out
        ],
        proof_a.key_hash,
    );
    verify_proof(
        proof_b.vkey,
        proof_b.proof,
        [
            proof_b.public_inputs[0], // comm_in
            proof_b.public_inputs[1], // comm_out
        ],
        proof_b.key_hash,
    );

    verify_proof(
        proof_c.vkey,
        proof_c.proof,
        prepare_proof_c_inputs(
            current_date,
            proof_c.public_inputs[0],
            proof_c.public_inputs[1],
        ),
        proof_c.key_hash,
    );

    verify_proof(
        proof_d.vkey,
        proof_d.proof,
        prepare_proof_d_inputs(
            proof_d.public_inputs[0], // comm_in
            dg1_mask,
            dg1_reveal,
            service_scope,
            service_subscope,
            scoped_nullifier,
        ),
        proof_d.key_hash,
    );
}

fn main(
    circuit_registry_root: Field,
    certificate_registry_root: Field,
    current_date: pub str<8>,
    dg1_mask: pub [u8; 95],
    dg1_reveal: pub [u8; 95],
    service_scope: pub Field,
    service_subscope: pub Field,
    scoped_nullifier: pub Field,
    proof_a: SubCircuitA,
    proof_b: SubCircuitB,
    proof_c: SubCircuitC,
    proof_d: SubCircuitD,
) {
    verify_subproofs(
        circuit_registry_root,
        certificate_registry_root,
        current_date,
        dg1_mask,
        dg1_reveal,
        service_scope,
        service_subscope,
        scoped_nullifier,
        proof_a,
        proof_b,
        proof_c,
        proof_d,
    );
    // verify_subproofs_unconstrained(circuit_registry_root, proof_a, proof_b, proof_c, proof_d);
}
