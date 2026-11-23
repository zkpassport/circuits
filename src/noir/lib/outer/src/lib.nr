use poseidon::poseidon2::Poseidon2;
use common::compute_merkle_root;
use std::verify_proof_with_type;
use utils::constants::{
    NON_SALTED_MOCK_NULLIFIER, NONE_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
};

global PROOF_TYPE_HONK_ZK: u32 = 6;

global PROOF_SIZE: u32 = 458;
global VKEY_SIZE: u32 = 115;

pub fn prepare_integrity_check_inputs(
    comm_in: Field,
    comm_out: Field,
    verification_method: Field,
) -> [Field; 3] {
    let mut result: [Field; 3] = [0; 3];
    result[0] = comm_in;
    result[1] = comm_out;
    result[2] = verification_method;
    result
}

pub fn prepare_disclosure_inputs(
    comm_in: Field,
    current_date: u64,
    param_commitment: Field,
    service_scope: Field,
    service_subscope: Field,
    nullifier_type: Field,
    scoped_nullifier: Field,
    oprf_pk_hash: Field,
) -> [Field; 8] {
    let mut result: [Field; 8] = [0; 8];
    result[0] = comm_in;
    result[1] = current_date as Field;
    result[2] = service_scope;
    result[3] = service_subscope;
    result[4] = param_commitment;
    result[5] = nullifier_type;
    result[6] = scoped_nullifier;
    result[7] = oprf_pk_hash;
    result
}

pub fn poseidon2_hash<let INPUT_LEN: u32>(input: [Field; INPUT_LEN]) -> Field {
    Poseidon2::hash(input, INPUT_LEN)
}

pub struct CSCtoDSCProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    // Excluding the certificate registry root
    // which is passed separately
    pub public_inputs: [Field; 1],
    pub key_hash: Field,
    // Hash path for circuit A key hash in the sub-circuit merkle tree
    // Allows for up to 4,096 leaves
    pub tree_hash_path: [Field; 12],
    // Index of circuit A key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct DSCtoIDDataProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    pub public_inputs: [Field; 2],
    pub key_hash: Field,
    // Hash path for circuit B key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit B key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct IntegrityCheckProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    // comm_in, comm_out, verification_method
    pub public_inputs: [Field; 3],
    pub key_hash: Field,
    // Hash path for circuit C key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit C key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct DisclosureProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    // comm_in, scoped_nullifier, nullifier_type, oprf_pk_hash
    pub public_inputs: [Field; 4],
    pub key_hash: Field,
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct AttestedIdProof<let N: u32> {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    // iOS: comm_out, param_commitment, verification_method
    // Android: current_date, comm_out, param_commitment, verification_method
    pub public_inputs: [Field; N],
    pub key_hash: Field,
    pub tree_hash_path: [Field; 12],
    pub tree_index: Field,
}

pub type AadhaarIdProof = AttestedIdProof<3>;

/// The checks every chip outer circuit (outer_count_{N+3}) makes on its subproofs: circuit-tree
/// membership and key hashes of every vkey, the nullifier rules, the recursive verification of each
/// subproof against the outer public inputs, and the commitment chain between them. Generic over
/// the number of disclosure proofs, so the outer circuits and other verifiers of the same subproofs
/// share one implementation.
pub fn verify_subproofs<let N: u32>(
    // Root of the Certificate Registry (v1 composed root)
    certificate_registry_root: Field,
    // Root of the circuit registry merkle tree
    circuit_registry_root: Field,
    // Current date and time as a unix timestamp
    current_date: u64,
    // The commitments over the parameters of the disclosure circuits
    param_commitments: [Field; N],
    // The nullifier service scope (a Pederson hash of the domain)
    service_scope: Field,
    // The service sub-scope
    service_subscope: Field,
    // The type of the nullifier
    nullifier_type: Field,
    // The scoped nullifier: H(private_nullifier,service_scope,service_subscope)
    scoped_nullifier: Field,
    // The hash of the OPRF public key used for salted nullifiers (0 if non-salted)
    oprf_pk_hash: Field,
    // What verified the ID, as the base proof output it
    verification_method: Field,
    csc_to_dsc_proof: CSCtoDSCProof,
    dsc_to_id_data_proof: DSCtoIDDataProof,
    integrity_check_proof: IntegrityCheckProof,
    disclosure_proofs: [DisclosureProof; N],
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
    assert_eq(poseidon2_hash(csc_to_dsc_proof.vkey), csc_to_dsc_proof.key_hash, "CSC to DSC proof vkey hash mismatch");
    assert_eq(poseidon2_hash(dsc_to_id_data_proof.vkey), dsc_to_id_data_proof.key_hash, "DSC to ID Data proof vkey hash mismatch");
    assert_eq(poseidon2_hash(integrity_check_proof.vkey), integrity_check_proof.key_hash, "Integrity check proof vkey hash mismatch");
    for i in 0..disclosure_proofs.len() {
        assert_eq(poseidon2_hash(disclosure_proofs[i].vkey), disclosure_proofs[i].key_hash, "Disclosure proof vkey hash mismatch");
    }

    // Only NONE proofs (or NON_SALTED_MOCK for ZKR IDs) may have a zero scoped nullifier
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
    // oprf_pk_hash is only meaningful for salted nullifiers
    assert(
        (nullifier_type == SALTED_NULLIFIER)
            | (nullifier_type == SALTED_MOCK_NULLIFIER)
            | (oprf_pk_hash == 0),
        "oprf_pk_hash must be zero unless the nullifier is salted",
    );

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
    assert_eq(csc_to_dsc_proof.public_inputs[0], dsc_to_id_data_proof.public_inputs[0], "Commitment out from CSC to DSC circuit != commitment in from DSC to ID Data circuit");

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
    assert_eq(dsc_to_id_data_proof.public_inputs[1], integrity_check_proof.public_inputs[0], "Commitment out from DSC to ID Data circuit != commitment in from integrity check circuit");

    verify_proof_with_type(
        integrity_check_proof.vkey,
        integrity_check_proof.proof,
        prepare_integrity_check_inputs(
            integrity_check_proof.public_inputs[0], // comm_in
            integrity_check_proof.public_inputs[1], // comm_out
            integrity_check_proof.public_inputs[2], // verification_method
        ),
        integrity_check_proof.key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    assert_eq(integrity_check_proof.public_inputs[2], verification_method, "Verification method from integrity check circuit != expected verification method");

    let mut found_valid_scoped_nullifier = false;

    for i in 0..disclosure_proofs.len() {
        // Commitment out from integrity check circuit == commitment in from disclosure circuit
        assert_eq(integrity_check_proof.public_inputs[1], disclosure_proofs[i].public_inputs[0], "Commitment out from integrity check circuit != commitment in from disclosure circuit");
        // Each disclosure subproof must either non-participate (== 0, or NONE for the nullifier type)
        // OR agree with the top-level value, for scoped_nullifier, nullifier_type, and oprf_pk_hash.
        // This allows circuits like facematch (which always emits 0 and NONE) to coexist with salted-participating circuits.
        assert((disclosure_proofs[i].public_inputs[1] == 0) | (disclosure_proofs[i].public_inputs[1] == scoped_nullifier), "Disclosure proof scoped nullifier must be either 0 or the expected scoped nullifier");
        assert((disclosure_proofs[i].public_inputs[2] == NONE_NULLIFIER) | (disclosure_proofs[i].public_inputs[2] == nullifier_type), "Disclosure proof nullifier type must be either NONE or the expected nullifier type");
        assert((disclosure_proofs[i].public_inputs[3] == 0) | (disclosure_proofs[i].public_inputs[3] == oprf_pk_hash), "Disclosure proof oprf_pk_hash must be either 0 or the expected oprf_pk_hash");
        // But at least one disclosure proof must have the expected scoped nullifier
        if (!found_valid_scoped_nullifier & (disclosure_proofs[i].public_inputs[1] == scoped_nullifier)) {
            found_valid_scoped_nullifier = true;
        }

        verify_proof_with_type(
            disclosure_proofs[i].vkey,
            disclosure_proofs[i].proof,
            prepare_disclosure_inputs(
                disclosure_proofs[i].public_inputs[0], // comm_in
                current_date,
                param_commitments[i],
                service_scope,
                service_subscope,
                disclosure_proofs[i].public_inputs[2], // nullifier_type (per-subproof: NONE or matches top-level)
                disclosure_proofs[i].public_inputs[1], // scoped nullifier (per-subproof: 0 or matches top-level)
                disclosure_proofs[i].public_inputs[3], // oprf_pk_hash (per-subproof: 0 or matches top-level)
            ),
            disclosure_proofs[i].key_hash,
            PROOF_TYPE_HONK_ZK,
        );
    }

    assert(found_valid_scoped_nullifier, "Incorrect scoped nullifier provided");
}

