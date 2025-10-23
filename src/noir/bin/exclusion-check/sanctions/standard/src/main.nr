use commitment::nullify;
use exclusion_check_sanctions::param_commit::calculate_param_commitment;
use exclusion_check_sanctions::{
    SanctionsSparseMerkleTrees, types::SanctionsOrderedMerkleTreeProofs,
};
use utils::{constants::PROOF_TYPE_SANCTIONS_EXCLUSION, types::DG1Data};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    proofs: SanctionsOrderedMerkleTreeProofs,
    root: Field,
    nullifier_secret: Field,
    is_strict: bool,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    let trees = SanctionsSparseMerkleTrees::default();
    assert(trees.root() == root);
    // Check that nationality of the passport holder is not in the list of countries
    trees.check_sanctions_exclusion(dg1, proofs, is_strict);
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salt,
        dg1,
        dg2_hash_normalized,
        dg2_hash_type,
        private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(PROOF_TYPE_SANCTIONS_EXCLUSION, root);
    (param_commitment, nullifier_type, nullifier)
}
