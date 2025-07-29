
type SanctionsSparseMerkleTreeProof = [Field; 254];

/// A proof for a single Sanctions sparse merkle tree
pub struct SanctionsMerkleProof {
    /// The leaf value used for a non inclusion check (common root)
    pub leaf_value: Field,
    /// The siblings of the leaf value
    pub siblings: SanctionsSparseMerkleTreeProof,
}

impl SanctionsMerkleProof {
    pub fn new(leaf_value: Field, siblings: SanctionsSparseMerkleTreeProof) -> Self {
        Self { leaf_value, siblings }
    }
}

/// A collection of proofs for the three Sanctions sparse merkle trees
pub struct SanctionsSparseMerkleTreeProofs {
    pub passportNoAndNationalitySMTProof: SanctionsMerkleProof,
    pub nameAndDobSMTProof: SanctionsMerkleProof,
    pub nameAndYobSMTProof: SanctionsMerkleProof,
}

impl SanctionsSparseMerkleTreeProofs {
    pub fn new(
        passportNoAndNationalitySMTProof: SanctionsMerkleProof,
        nameAndDobSMTProof: SanctionsMerkleProof,
        nameAndYobSMTProof: SanctionsMerkleProof,
    ) -> Self {
        Self { passportNoAndNationalitySMTProof, nameAndDobSMTProof, nameAndYobSMTProof }
    }
}