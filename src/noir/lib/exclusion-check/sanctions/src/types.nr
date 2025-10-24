pub global SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH: u32 = 18;

type SanctionsOrderedMerkleTreeSiblingPath = [Field; SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH];

pub struct SanctionsOrderedMerkleTreeInclusionProof {
    pub leaf: Field,
    pub leaf_index: Field,
    pub sibling_path: SanctionsOrderedMerkleTreeSiblingPath,
}

/// A proof for a single Sanctions sparse merkle tree
pub struct SanctionsOrderedMerkleTreeProof {
    /// The siblings of the leaf value
    pub left: SanctionsOrderedMerkleTreeInclusionProof,
    pub right: SanctionsOrderedMerkleTreeInclusionProof,
}

impl SanctionsOrderedMerkleTreeProof {
    pub fn new(
        left: SanctionsOrderedMerkleTreeInclusionProof,
        right: SanctionsOrderedMerkleTreeInclusionProof,
    ) -> Self {
        Self { left, right }
    }
}

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
