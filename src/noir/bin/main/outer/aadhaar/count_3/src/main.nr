// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
/*
############################################################
# Outer Circuit, Aadhaar
############################################################
# Wraps 3 subproofs (the aadhaar_id base proof + 2 disclosure proofs)
# into a single proof by verifying them recursively. The aadhaar_id proof stands in for the three
# chip base proofs; the Certificate Registry root it proved the UIDAI key under is this proof's
# certificate_registry_root, which the verifier checks as for a chip ID. The verifier must also
# require a face match among the disclosure proofs, as anyone with a copy of the QR code could
# otherwise prove with it.
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> The Certificate Registry root the UIDAI key is under
circuit_registry_root -> The root of the circuit registry merkle tree
current_date -> The current date as a unix timestamp
service_scope -> The service scope
service_subscope -> The service subscope
param_commitments -> The parameter commitments of the disclosure circuits
nullifier_type -> The type of the nullifier
scoped_nullifier -> The scoped nullifier
oprf_pk_hash -> The hash of the OPRF public key used for salted nullifiers (0 if non-salted)
credential_scheme -> CREDENTIAL_SCHEME_UIDAI_AADHAAR, as the aadhaar_id proof outputs
aadhaar_id_proof -> The proof of the aadhaar_id circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

use common::compute_merkle_root;
use outer_lib::{AadhaarIdProof, DisclosureProof, poseidon2_hash, prepare_disclosure_inputs};
use std::verify_proof_with_type;
use utils::constants::{
    CREDENTIAL_SCHEME_UIDAI_AADHAAR, NON_SALTED_MOCK_NULLIFIER, NONE_NULLIFIER,
    SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
};
global PROOF_TYPE_HONK_ZK: u32 = 6;

fn main(
    certificate_registry_root: pub Field,
    circuit_registry_root: pub Field,
    current_date: pub u64,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; 2],
    nullifier_type: pub Field,
    scoped_nullifier: pub Field,
    oprf_pk_hash: pub Field,
    credential_scheme: pub Field,
    aadhaar_id_proof: AadhaarIdProof,
    disclosure_proofs: [DisclosureProof; 2],
) {
    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            aadhaar_id_proof.key_hash,
            aadhaar_id_proof.tree_index,
            aadhaar_id_proof.tree_hash_path,
        ),
        "Aadhaar ID proof vkey hash not found in circuit tree",
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
    assert_eq(
        poseidon2_hash(aadhaar_id_proof.vkey),
        aadhaar_id_proof.key_hash,
        "Aadhaar ID proof vkey hash mismatch",
    );
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            poseidon2_hash(disclosure_proofs[i].vkey),
            disclosure_proofs[i].key_hash,
            "Disclosure proof vkey hash mismatch",
        );
    }

    assert(
        (scoped_nullifier != 0)
            | (nullifier_type == NONE_NULLIFIER)
            | (nullifier_type == NON_SALTED_MOCK_NULLIFIER),
        "Scoped nullifier must be non-zero unless the nullifier type is NONE",
    );
    assert(
        (scoped_nullifier == 0) | (nullifier_type != NONE_NULLIFIER),
        "Scoped nullifier must be zero when the nullifier type is NONE",
    );
    assert(
        (nullifier_type == SALTED_NULLIFIER)
            | (nullifier_type == SALTED_MOCK_NULLIFIER)
            | (oprf_pk_hash == 0),
        "oprf_pk_hash must be zero unless the nullifier is salted",
    );

    // Only aadhaar_id outputs this scheme, which also keeps any other circuit with as many public
    // inputs out of the base proof's place
    assert_eq(
        credential_scheme,
        CREDENTIAL_SCHEME_UIDAI_AADHAAR,
        "Not the Aadhaar credential scheme",
    );
    assert_eq(
        aadhaar_id_proof.public_inputs[0],
        certificate_registry_root,
        "Certificate registry root from Aadhaar ID circuit != expected certificate registry root",
    );
    let comm_out = aadhaar_id_proof.public_inputs[1];
    assert_eq(
        aadhaar_id_proof.public_inputs[2],
        credential_scheme,
        "Credential scheme from Aadhaar ID circuit != expected credential scheme",
    );

    verify_proof_with_type(
        aadhaar_id_proof.vkey,
        aadhaar_id_proof.proof,
        aadhaar_id_proof.public_inputs,
        aadhaar_id_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    let mut found_valid_scoped_nullifier = false;
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            comm_out,
            disclosure_proofs[i].public_inputs[0],
            "Commitment out from Aadhaar ID circuit != commitment in from disclosure circuit",
        );
        assert(
            (disclosure_proofs[i].public_inputs[1] == 0)
                | (disclosure_proofs[i].public_inputs[1] == scoped_nullifier),
            "Disclosure proof scoped nullifier must be either 0 or the expected scoped nullifier",
        );
        assert(
            (disclosure_proofs[i].public_inputs[2] == NONE_NULLIFIER)
                | (disclosure_proofs[i].public_inputs[2] == nullifier_type),
            "Disclosure proof nullifier type must be either NONE or the expected nullifier type",
        );
        assert(
            (disclosure_proofs[i].public_inputs[3] == 0)
                | (disclosure_proofs[i].public_inputs[3] == oprf_pk_hash),
            "Disclosure proof oprf_pk_hash must be either 0 or the expected oprf_pk_hash",
        );
        if (
            !found_valid_scoped_nullifier
                & (disclosure_proofs[i].public_inputs[1] == scoped_nullifier)
        ) {
            found_valid_scoped_nullifier = true;
        }

        verify_proof_with_type(
            disclosure_proofs[i].vkey,
            disclosure_proofs[i].proof,
            prepare_disclosure_inputs(
                disclosure_proofs[i].public_inputs[0],
                current_date,
                param_commitments[i],
                service_scope,
                service_subscope,
                disclosure_proofs[i].public_inputs[2],
                disclosure_proofs[i].public_inputs[1],
                disclosure_proofs[i].public_inputs[3],
            ),
            disclosure_proofs[i].key_hash,
            PROOF_TYPE_HONK_ZK,
        );
    }

    assert(found_valid_scoped_nullifier, "Incorrect scoped nullifier provided");
}
