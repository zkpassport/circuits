use commitment::nullify;
use data_check_expiry::check_expiry;
use exclusion_check_sanctions::param_commit::calculate_param_commitment;
use exclusion_check_sanctions::{
    SanctionsSparseMerkleTrees, types::SanctionsOrderedMerkleTreeProofs,
};
use utils::types::{DG1Data, SaltedValue};
use utils::types::MRZExpiryDate;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    proofs: SanctionsOrderedMerkleTreeProofs,
    root: Field,
    nullifier_secret: Field,
    oprf_proof: commitment::OPRFProof,
    is_strict: bool,
    service_scope: pub Field,
    service_subscope: pub Field,
    // What verified the ID (CREDENTIAL_SCHEME_* in utils); the outer circuit and the verifier
    // check it against the base proof's output, so it rides along as the last public output
    credential_scheme: Field,
) -> pub (Field, Field, Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    let trees = SanctionsSparseMerkleTrees::new(root);
    // Check that nationality of the passport holder is not in the list of countries
    trees.check_sanctions_exclusion(salted_dg1.value, proofs, is_strict);
    let (nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
        oprf_proof,
    );
    let param_commitment = calculate_param_commitment(root, is_strict);
    assert(credential_scheme != 0, "Credential scheme must be set");
    (param_commitment, nullifier_type, nullifier, oprf_pk_hash, credential_scheme)
}
