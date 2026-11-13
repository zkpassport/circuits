// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
/*
############################################################
# Outer Circuit, Tier 2 (Android)
############################################################
# Wraps 5 subproofs (the attested ID base proof + 4 disclosure proofs)
# into a single proof by verifying them recursively. The attested ID proof stands in for the three
# chip base proofs; its device attestation parameters are the first parameter commitment, which
# the verifier must check (the circuit cannot know which attestation root keys are genuine).
############################################################

# Inputs/Outputs
############################################################
certificate_registry_root -> Unused by a camera-read ID; kept so the public inputs keep the chip outer's layout
circuit_registry_root -> The root of the circuit registry merkle tree
current_date -> The current date as a unix timestamp
service_scope -> The service scope
service_subscope -> The service subscope
param_commitments -> The attested ID proof's parameter commitment, then those of the disclosure circuits
nullifier_type -> The type of the nullifier
scoped_nullifier -> The scoped nullifier
oprf_pk_hash -> The hash of the OPRF public key used for salted nullifiers (0 if non-salted)
credential_scheme -> CREDENTIAL_SCHEME_ATTESTED_CAPTURE_ANDROID
attested_id_proof -> The proof of the attested ID circuit
disclosure_proofs -> The proofs of the disclosure circuits
*/

use common::compute_merkle_root;
use outer_lib::{AttestedIdProof, DisclosureProof, poseidon2_hash, prepare_disclosure_inputs};
use std::verify_proof_with_type;
use utils::constants::{
    CREDENTIAL_SCHEME_ATTESTED_CAPTURE_ANDROID, NON_SALTED_MOCK_NULLIFIER, NONE_NULLIFIER,
    SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
};
global PROOF_TYPE_HONK_ZK: u32 = 6;
// How old the attestation may be, and how far ahead of the outer proof's date for clock skew
global ATTESTED_ID_PROOF_MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
global ATTESTED_ID_PROOF_MAX_SKEW_SECONDS: u64 = 24 * 60 * 60;

fn main(
    certificate_registry_root: pub Field,
    circuit_registry_root: pub Field,
    current_date: pub u64,
    service_scope: pub Field,
    service_subscope: pub Field,
    param_commitments: pub [Field; 5],
    nullifier_type: pub Field,
    scoped_nullifier: pub Field,
    oprf_pk_hash: pub Field,
    credential_scheme: pub Field,
    attested_id_proof: AttestedIdProof<4>,
    disclosure_proofs: [DisclosureProof; 4],
) {
    let _ = certificate_registry_root;

    assert_eq(
        circuit_registry_root,
        compute_merkle_root(
            attested_id_proof.key_hash,
            attested_id_proof.tree_index,
            attested_id_proof.tree_hash_path,
        ),
        "Attested ID proof vkey hash not found in circuit tree",
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
        poseidon2_hash(attested_id_proof.vkey),
        attested_id_proof.key_hash,
        "Attested ID proof vkey hash mismatch",
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

    // The scheme only the attested ID circuits of this platform output, which also keeps any other
    // circuit with as many public inputs out of the base proof's place
    assert_eq(
        credential_scheme,
        CREDENTIAL_SCHEME_ATTESTED_CAPTURE_ANDROID,
        "Not a Tier 2 credential scheme for this platform",
    );
    // The attestation's date: the integrity token's on Android, the App Attest credential
    // certificate's notBefore on iOS (a fresh key is attested for every face match)
    let attested_date = attested_id_proof.public_inputs[0] as u64;
    let comm_out = attested_id_proof.public_inputs[1];
    let attested_param_commitment = attested_id_proof.public_inputs[2];
    let attested_scheme = attested_id_proof.public_inputs[3];
    assert(
        (attested_date <= current_date + ATTESTED_ID_PROOF_MAX_SKEW_SECONDS)
            & (current_date <= attested_date + ATTESTED_ID_PROOF_MAX_AGE_SECONDS),
        "Attested ID proof is not recent",
    );
    assert_eq(
        attested_scheme,
        credential_scheme,
        "Credential scheme from attested ID circuit != expected credential scheme",
    );
    assert_eq(
        attested_param_commitment,
        param_commitments[0],
        "Attested ID parameter commitment != first parameter commitment",
    );

    verify_proof_with_type(
        attested_id_proof.vkey,
        attested_id_proof.proof,
        attested_id_proof.public_inputs,
        attested_id_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    let mut found_valid_scoped_nullifier = false;
    for i in 0..disclosure_proofs.len() {
        assert_eq(
            comm_out,
            disclosure_proofs[i].public_inputs[0],
            "Commitment out from attested ID circuit != commitment in from disclosure circuit",
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
                param_commitments[i + 1],
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
