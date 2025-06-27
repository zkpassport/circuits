use commitment::nullify;
use utils::{PROOF_TYPE_OFAC_EXCLUSION};
use exclusion_check_sanctions::param_commit::calculate_param_commitment_sha2;
use exclusion_check_sanctions::{OFACSparseMerkleTrees, types::OFACSparseMerkleTreeProofs};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    root_hash: Field,
    proofs: OFACSparseMerkleTreeProofs,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let trees = OFACSparseMerkleTrees::default();
    assert(trees.root_hash() == root_hash);
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
    let param_commitment = calculate_param_commitment_sha2(PROOF_TYPE_OFAC_EXCLUSION, root_hash);
    (param_commitment, nullifier)
}
