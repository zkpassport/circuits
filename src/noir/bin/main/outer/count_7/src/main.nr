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
certificate_registry_root -> The published Certificate Registry root (v1: H(packed(schema_version || timestamp), state_root))
circuit_registry_root -> The root of the circuit registry merkle tree
current_date -> The current date as a string, e.g. 20241103 (used by the integrity check subproof)
service_scope -> The service scope
service_subscope -> The service subscope
param_commitments -> The commitments over the parameters of the disclosure circuits
nullifier_type -> The type of the nullifier
scoped_nullifier -> The scoped nullifier
verification_method -> What verified the ID (VERIFICATION_METHOD_* in utils): 1xx when the issuer signed it, 2xx when a device attested a camera read of it
csc_to_dsc_proof -> The proof of the CSC to DSC circuit
dsc_to_id_data_proof -> The proof of the DSC to ID Data circuit
integrity_check_proof -> The proof of the integrity check circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

use outer_lib::{
    CSCtoDSCProof, DisclosureProof, DSCtoIDDataProof, IntegrityCheckProof, verify_subproofs,
};

fn main(
    // Root of the Certificate Registry (v1 composed root)
    certificate_registry_root: pub Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: pub Field,
    current_date: pub u64,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; 4],
    nullifier_type: pub Field,
    scoped_nullifier: pub Field,
    oprf_pk_hash: pub Field,
    verification_method: pub Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; 4],
) {
    verify_subproofs(
        certificate_registry_root,
        circuit_registry_root,
        current_date,
        param_commitments,
        service_scope,
        service_subscope,
        nullifier_type,
        scoped_nullifier,
        oprf_pk_hash,
        verification_method,
        csc_to_dsc_proof,
        dsc_to_id_data_proof,
        integrity_check_proof,
        disclosure_proofs,
    );
}
