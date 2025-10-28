use commitment::nullify;
use data_check_expiry::check_expiry;
use exclusion_check_sanctions::param_commit::calculate_param_commitment_sha2;
use exclusion_check_sanctions::{
    SanctionsSparseMerkleTrees, types::SanctionsOrderedMerkleTreeProofs,
};
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    root: Field,
    proofs: SanctionsOrderedMerkleTreeProofs,
    is_strict: bool,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(dg1, current_date);

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
    let param_commitment = calculate_param_commitment_sha2(root, is_strict);
    (param_commitment, nullifier_type, nullifier)
}
