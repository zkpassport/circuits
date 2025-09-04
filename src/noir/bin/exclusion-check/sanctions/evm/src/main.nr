use commitment::nullify;
use exclusion_check_sanctions::param_commit::calculate_param_commitment_sha2;
use exclusion_check_sanctions::{
    SanctionsSparseMerkleTrees, types::SanctionsOrderedMerkleTreeProofs,
};
use utils::PROOF_TYPE_SANCTIONS_EXCLUSION;


fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    root: Field,
    proofs: SanctionsOrderedMerkleTreeProofs,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // So is the plan to always hard-code the root in the circuit, or to instead
    // have the root be a public input (or committed into param_commitment) so that
    // the list can be more-easily updated onchain?
    // Iiuc, it might make more sense to not have a hard-coded root, and instead
    // instantiate this as:
    // `trees = SanctionsSparseMerkleTrees { root };` using the circuit private input `root`,
    // then checking that root within the Verifier.
    // Also "trees" (plural) is confusing, because it appears to be just one big tree,
    // which contains leaves that might represent one of three different concepts.
    let trees = SanctionsSparseMerkleTrees::default();
    assert(trees.root() == root);
    // Check that nationality of the passport holder is not in the list of countries
    trees.check_sanctions_exclusion(dg1, proofs);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    let param_commitment = calculate_param_commitment_sha2(PROOF_TYPE_SANCTIONS_EXCLUSION, root);
    (param_commitment, nullifier)
}
