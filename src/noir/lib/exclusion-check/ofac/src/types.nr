
type OFACSparseMerkleTreeProof = [Field; 254];

/// A proof for a single OFAC sparse merkle tree
pub struct OFACMerkleProof {
    /// The leaf value used for a non inclusion check (common root)
    pub leaf_value: Field,
    /// The siblings of the leaf value
    pub siblings: OFACSparseMerkleTreeProof,
}

impl OFACMerkleProof {
    pub fn new(leaf_value: Field, siblings: OFACSparseMerkleTreeProof) -> Self {
        Self { leaf_value, siblings }
    }
}

/// A collection of proofs for the three OFAC sparse merkle trees
pub struct OFACSparseMerkleTreeProofs {
    pub passportNoAndNationalitySMTProof: OFACMerkleProof,
    pub nameAndDobSMTProof: OFACMerkleProof,
    pub nameAndYobSMTProof: OFACMerkleProof,
}

impl OFACSparseMerkleTreeProofs {
    pub fn new(
        passportNoAndNationalitySMTProof: OFACMerkleProof,
        nameAndDobSMTProof: OFACMerkleProof,
        nameAndYobSMTProof: OFACMerkleProof,
    ) -> Self {
        Self { passportNoAndNationalitySMTProof, nameAndDobSMTProof, nameAndYobSMTProof }
    }
}