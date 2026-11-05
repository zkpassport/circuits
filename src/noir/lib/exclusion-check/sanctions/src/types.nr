use utils::ordered_mt::{OrderedMerkleTreeInclusionProof, OrderedMerkleTreeProof};

pub global SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH: u32 = 18;

pub type SanctionsOrderedMerkleTreeInclusionProof = OrderedMerkleTreeInclusionProof<SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH>;

/// A proof for a single Sanctions sparse merkle tree
pub type SanctionsOrderedMerkleTreeProof = OrderedMerkleTreeProof<SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH>;

/// A collection of proofs for the three Sanctions sparse merkle trees
pub struct SanctionsOrderedMerkleTreeProofs {
    pub name_proofs: [SanctionsOrderedMerkleTreeProof; 3],
    pub passport_no_and_nationality_proof: SanctionsOrderedMerkleTreeProof,
    pub name_and_dob_proofs: [SanctionsOrderedMerkleTreeProof; 3],
    pub name_and_yob_proofs: [SanctionsOrderedMerkleTreeProof; 3],
}

impl SanctionsOrderedMerkleTreeProofs {
    pub fn new(
        name_proofs: [SanctionsOrderedMerkleTreeProof; 3],
        passport_no_and_nationality_proof: SanctionsOrderedMerkleTreeProof,
        name_and_dob_proofs: [SanctionsOrderedMerkleTreeProof; 3],
        name_and_yob_proofs: [SanctionsOrderedMerkleTreeProof; 3],
    ) -> Self {
        Self {
            name_proofs,
            passport_no_and_nationality_proof,
            name_and_dob_proofs,
            name_and_yob_proofs,
        }
    }
}
