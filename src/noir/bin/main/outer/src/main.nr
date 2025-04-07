/*
############################################################
# Outer Circuit
############################################################
# Wraps 4 subproofs (3 base proofs + 1 disclosure proof) into a single proof 
# by verifying them recursively
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> The root of the certificate registry merkle tree
current_date -> The current date as a string, e.g. 20241103 (used by the integrity check subproof)
service_scope -> The service scope
service_subscope -> The service subscope
param_commitment -> The commitment over the parameters of the disclosure circuit
scoped_nullifier -> The scoped nullifier
proof_csc_to_dsc -> The proof of the CSC to DSC subproof
proof_dsc_to_id_data -> The proof of the DSC to ID Data subproof
proof_integrity_check -> The proof of the integrity check subproof
proof_disclosure -> The proof of the disclosure subproof
*/

//use common::compute_merkle_root;
use std::verify_proof;

global PROOF_SIZE: u32 = 439;
global VKEY_SIZE: u32 = 128;

fn prepare_proof_c_inputs<let DATE_LEN: u32>(
    current_date: str<DATE_LEN>,
    comm_in: Field,
    comm_out: Field,
) -> [Field; DATE_LEN + 2] {
    let date_bytes: [u8; DATE_LEN] = current_date.as_bytes();
    let mut result: [Field; 2 + DATE_LEN] = [0; 2 + DATE_LEN];
    result[0] = comm_in;
    for i in 0..DATE_LEN {
        result[i + 1] = date_bytes[i] as Field;
    }
    result[DATE_LEN + 1] = comm_out;
    result
}

fn prepare_proof_d_inputs(
    comm_in: Field,
    param_commitment: Field,
    service_scope: Field,
    service_subscope: Field,
    scoped_nullifier: Field,
) -> [Field; 5] {
    let mut result: [Field; 5] = [0; 5];
    result[0] = comm_in;
    result[1] = service_scope;
    result[2] = service_subscope;
    result[3] = param_commitment;
    result[4] = scoped_nullifier;
    result
}

struct CSCtoDSCProof {
    vkey: [Field; VKEY_SIZE],
    proof: [Field; PROOF_SIZE],
    // Excluding the certificate registry root
    // which is passed separately
    public_inputs: [Field; 1],
    key_hash: Field,
    // TODO: enable it when the circuit registry is ready
    // Hash path for circuit A key hash in the sub-circuit merkle tree
    // Allows for up to 4,096 leaves
    // tree_hash_path: [Field; 12],
    // Index of circuit A key hash in the sub-circuit merkle tree
    // tree_index: Field,
}
struct DSCtoIDDataProof {
    vkey: [Field; VKEY_SIZE],
    proof: [Field; PROOF_SIZE],
    public_inputs: [Field; 2],
    key_hash: Field,
    // TODO: enable it when the circuit registry is ready
    // Hash path for circuit B key hash in the sub-circuit merkle tree
    // tree_hash_path: [Field; 12],
    // Index of circuit B key hash in the sub-circuit merkle tree
    // tree_index: Field,
}
struct IntegrityCheckProof {
    vkey: [Field; VKEY_SIZE],
    proof: [Field; PROOF_SIZE],
    public_inputs: [Field; 2],
    key_hash: Field,
    // TODO: enable it when the circuit registry is ready
    // Hash path for circuit C key hash in the sub-circuit merkle tree
    // tree_hash_path: [Field; 12],
    // Index of circuit C key hash in the sub-circuit merkle tree
    // tree_index: Field,
}
struct DisclosureProof {
    vkey: [Field; VKEY_SIZE],
    proof: [Field; PROOF_SIZE],
    public_inputs: [Field; 1],
    key_hash: Field,
    // TODO: enable it when the circuit registry is ready
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    // tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    // tree_index: Field,
}

fn verify_subproofs(
    // Root of the sub-circuit merkle tree
    // TODO: enable it when the circuit registry is ready
    // circuit_registry_root: Field,
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Current date as a string, e.g. 20241103
    current_date: str<8>,
    // The commitment over the parameters of the disclosure circuit
    param_commitment: Field,
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    proof_csc_to_dsc: CSCtoDSCProof,
    proof_dsc_to_id_data: DSCtoIDDataProof,
    proof_integrity_check: IntegrityCheckProof,
    proof_disclosure: DisclosureProof,
) {
    // Verify that sub-circuit a, b, c, and d vkey hashes exist in the circuit tree
    // TODO: enable it when the circuit registry is ready
    /*let root = compute_merkle_root(proof_a.key_hash, proof_a.tree_index, proof_a.tree_hash_path);
    assert(root == circuit_registry_root);
    let root = compute_merkle_root(proof_b.key_hash, proof_b.tree_index, proof_b.tree_hash_path);
    assert(root == circuit_registry_root);
    let root = compute_merkle_root(proof_c.key_hash, proof_c.tree_index, proof_c.tree_hash_path);
    assert(root == circuit_registry_root);
    let root = compute_merkle_root(proof_d.key_hash, proof_d.tree_index, proof_d.tree_hash_path);
    assert(root == circuit_registry_root);*/

    verify_proof(
        proof_csc_to_dsc.vkey,
        proof_csc_to_dsc.proof,
        [
            certificate_registry_root,
            proof_csc_to_dsc.public_inputs[0], // comm_out
        ],
        proof_csc_to_dsc.key_hash,
    );
    verify_proof(
        proof_dsc_to_id_data.vkey,
        proof_dsc_to_id_data.proof,
        [
            proof_dsc_to_id_data.public_inputs[0], // comm_in
            proof_dsc_to_id_data.public_inputs[1], // comm_out
        ],
        proof_dsc_to_id_data.key_hash,
    );

    verify_proof(
        proof_integrity_check.vkey,
        proof_integrity_check.proof,
        prepare_proof_c_inputs(
            current_date,
            proof_integrity_check.public_inputs[0], // comm_in
            proof_integrity_check.public_inputs[1], // comm_out
        ),
        proof_integrity_check.key_hash,
    );

    verify_proof(
        proof_disclosure.vkey,
        proof_disclosure.proof,
        prepare_proof_d_inputs(
            proof_disclosure.public_inputs[0], // comm_in
            param_commitment,
            service_scope,
            service_subscope,
            scoped_nullifier,
        ),
        proof_disclosure.key_hash,
    );
}

fn main(
    // TODO: enable it when the circuit registry is ready
    // circuit_registry_root: pub Field,
    certificate_registry_root: pub Field,
    current_date: pub str<8>,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitment: pub Field,
    scoped_nullifier: pub Field,
    proof_csc_to_dsc: CSCtoDSCProof,
    proof_dsc_to_id_data: DSCtoIDDataProof,
    proof_integrity_check: IntegrityCheckProof,
    proof_disclosure: DisclosureProof,
) {
    verify_subproofs(
        certificate_registry_root,
        current_date,
        param_commitment,
        service_scope,
        service_subscope,
        scoped_nullifier,
        proof_csc_to_dsc,
        proof_dsc_to_id_data,
        proof_integrity_check,
        proof_disclosure,
    );
}
