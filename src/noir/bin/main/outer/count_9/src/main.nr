// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
/*
############################################################
# Outer Circuit
############################################################
# Wraps 9 subproofs (3 base proofs + 6 disclosure proofs) into a single proof
# by verifying them recursively
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> The root of the certificate registry merkle tree
circuit_registry_root -> The root of the circuit registry merkle tree
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

use common::compute_merkle_root;
use outer_lib::{
    CSCtoDSCProof, DisclosureProof, DSCtoIDDataProof, IntegrityCheckProof, poseidon2_hash,
    prepare_disclosure_inputs, prepare_integrity_check_inputs,
};
use std::verify_proof_with_type;
global PROOF_TYPE_HONK_ZK: u32 = 7;

fn verify_subproofs(
    // Root of the certificate merkle tree
    certificate_registry_root: Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: Field,
    // Current date and time as a unix timestamp
    timestamp: u32,
    // The commitments over the parameters of the disclosure circuits
    param_commitments: [Field; 6],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; 6],
) {
    // Verify that all subproofs vkey hashes exist in the circuit tree
    // This way we know for sure that the proofs were generated with valid circuits
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            csc_to_dsc_proof.key_hash,
            csc_to_dsc_proof.tree_index,
            csc_to_dsc_proof.tree_hash_path,
        ),
        "CSC to DSC proof vkey hash not found in circuit tree",
    );
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            dsc_to_id_data_proof.key_hash,
            dsc_to_id_data_proof.tree_index,
            dsc_to_id_data_proof.tree_hash_path,
        ),
        "DSC to ID Data proof vkey hash not found in circuit tree",
    );
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            integrity_check_proof.key_hash,
            integrity_check_proof.tree_index,
            integrity_check_proof.tree_hash_path,
        ),
        "Integrity check proof vkey hash not found in circuit tree",
    );
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            circuit_registry_root,
            compute_merkle_root(
                disclosure_proofs[i].key_hash,
                disclosure_proofs[i].tree_index,
                disclosure_proofs[i].tree_hash_path,
            ),
            "Disclosure proof vkey hash not found in circuit tree",
        );
    }

    // Verify that the vkey hashes are correct
    assert_eq(
        poseidon2_hash(csc_to_dsc_proof.vkey),
        csc_to_dsc_proof.key_hash,
        "CSC to DSC proof vkey hash mismatch",
    );
    assert_eq(
        poseidon2_hash(dsc_to_id_data_proof.vkey),
        dsc_to_id_data_proof.key_hash,
        "DSC to ID Data proof vkey hash mismatch",
    );
    assert_eq(
        poseidon2_hash(integrity_check_proof.vkey),
        integrity_check_proof.key_hash,
        "Integrity check proof vkey hash mismatch",
    );
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            poseidon2_hash(disclosure_proofs[i].vkey),
            disclosure_proofs[i].key_hash,
            "Disclosure proof vkey hash mismatch",
        );
    }

    verify_proof_with_type(
        csc_to_dsc_proof.vkey,
        csc_to_dsc_proof.proof,
        [
            certificate_registry_root,
            csc_to_dsc_proof.public_inputs[0], // comm_out
        ],
        csc_to_dsc_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    // Commitment out from CSC to DSC circuit == commitment in from DSC to ID Data circuit
    assert_eq(
        csc_to_dsc_proof.public_inputs[0],
        dsc_to_id_data_proof.public_inputs[0],
        "Commitment out from CSC to DSC circuit != commitment in from DSC to ID Data circuit",
    );

    verify_proof_with_type(
        dsc_to_id_data_proof.vkey,
        dsc_to_id_data_proof.proof,
        [
            dsc_to_id_data_proof.public_inputs[0], // comm_in
            dsc_to_id_data_proof.public_inputs[1], // comm_out
        ],
        dsc_to_id_data_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    // Commitment out from DSC to ID Data circuit == commitment in from integrity check circuit
    assert_eq(
        dsc_to_id_data_proof.public_inputs[1],
        integrity_check_proof.public_inputs[0],
        "Commitment out from DSC to ID Data circuit != commitment in from integrity check circuit",
    );

    verify_proof_with_type(
        integrity_check_proof.vkey,
        integrity_check_proof.proof,
        prepare_integrity_check_inputs(
            timestamp,
            integrity_check_proof.public_inputs[0], // comm_in
            integrity_check_proof.public_inputs[1], // comm_out
        ),
        integrity_check_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    for i in 0..disclosure_proofs.len() {
        // Commitment out from integrity check circuit == commitment in from disclosure circuit
        assert_eq(
            integrity_check_proof.public_inputs[1],
            disclosure_proofs[i].public_inputs[0],
            "Commitment out from integrity check circuit != commitment in from disclosure circuit",
        );

        verify_proof_with_type(
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
            PROOF_TYPE_HONK_ZK,
        );
    }
}

fn main(
    // Root of the certificate registry merkle tree
    certificate_registry_root: pub Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: pub Field,
    timestamp: pub u32,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; 6],
    scoped_nullifier: pub Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; 6],
) {
    verify_subproofs(
        certificate_registry_root,
        circuit_registry_root,
        timestamp,
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
