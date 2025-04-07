// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
/*
############################################################
# Outer Circuit
############################################################
# Wraps 7 subproofs (3 base proofs + 4 disclosure proofs) into a single proof 
# by verifying them recursively
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> The root of the certificate registry merkle tree
current_date -> The current date as a string, e.g. 20241103 (used by the integrity check subproof)
service_scope -> The service scope
service_subscope -> The service subscope
param_commitments -> The commitments over the parameters of the disclosure circuits
scoped_nullifier -> The scoped nullifier
csc_to_dsc_proof -> The proof of the CSC to DSC circuit
dsc_to_id_data_proof -> The proof of the DSC to ID Data circuit
integrity_check_proof -> The proof of the integrity check circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

//use common::compute_merkle_root;
use outer_lib::{
    CSCtoDSCProof, DisclosureProof, DSCtoIDDataProof, IntegrityCheckProof,
    prepare_disclosure_inputs, prepare_integrity_check_inputs,
};
use std::verify_proof;

fn verify_subproofs(
    // Root of the sub-circuit merkle tree
    // TODO: enable it when the circuit registry is ready
    // circuit_registry_root: Field,
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Current date as a string, e.g. 20241103
    current_date: str<8>,
    // The commitments over the parameters of the disclosure circuits
    param_commitments: [Field; 4],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; 4],
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
        csc_to_dsc_proof.vkey,
        csc_to_dsc_proof.proof,
        [
            certificate_registry_root,
            csc_to_dsc_proof.public_inputs[0], // comm_out
        ],
        csc_to_dsc_proof.key_hash,
    );
    verify_proof(
        dsc_to_id_data_proof.vkey,
        dsc_to_id_data_proof.proof,
        [
            dsc_to_id_data_proof.public_inputs[0], // comm_in
            dsc_to_id_data_proof.public_inputs[1], // comm_out
        ],
        dsc_to_id_data_proof.key_hash,
    );

    verify_proof(
        integrity_check_proof.vkey,
        integrity_check_proof.proof,
        prepare_integrity_check_inputs(
            current_date,
            integrity_check_proof.public_inputs[0], // comm_in
            integrity_check_proof.public_inputs[1], // comm_out
        ),
        integrity_check_proof.key_hash,
    );

    for i in 0..disclosure_proofs.len() {
        verify_proof(
            disclosure_proofs[i].vkey,
            disclosure_proofs[i].proof,
            prepare_disclosure_inputs(
                disclosure_proofs[i].public_inputs[0], // comm_in
                param_commitments[i],
                service_scope,
                service_subscope,
                scoped_nullifier,
            ),
            disclosure_proofs[i].key_hash,
        );
    }
}

fn main(
    // TODO: enable it when the circuit registry is ready
    // circuit_registry_root: pub Field,
    certificate_registry_root: pub Field,
    current_date: pub str<8>,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; 4],
    scoped_nullifier: pub Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; 4],
) {
    verify_subproofs(
        certificate_registry_root,
        current_date,
        param_commitments,
        service_scope,
        service_subscope,
        scoped_nullifier,
        csc_to_dsc_proof,
        dsc_to_id_data_proof,
        integrity_check_proof,
        disclosure_proofs,
    );
}