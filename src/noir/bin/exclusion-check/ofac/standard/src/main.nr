use commitment::nullify;
use exclusion_check_ofac::{check_ofac_exclusion, OFACSparseMerkleTrees, OFACSparseMerkleTreeProofs};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    proofs: OFACSparseMerkleTreeProofs,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    let trees = OFACSparseMerkleTrees::default();
    // Check that nationality of the passport holder is not in the list of countries
    trees.check_ofac_exclusion(dg1, proofs);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    nullifier
}

