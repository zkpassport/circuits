use poseidon::poseidon2::Poseidon2;

pub struct OrderedMerkleTreeInclusionProof<let DEPTH: u32> {
    pub leaf: Field,
    pub leaf_index: Field,
    pub sibling_path: [Field; DEPTH],
}

/// The two adjacent leaves of an ordered Merkle tree that a value falls strictly between
pub struct OrderedMerkleTreeProof<let DEPTH: u32> {
    pub left: OrderedMerkleTreeInclusionProof<DEPTH>,
    pub right: OrderedMerkleTreeInclusionProof<DEPTH>,
}

impl<let DEPTH: u32> OrderedMerkleTreeProof<DEPTH> {
    pub fn new(
        left: OrderedMerkleTreeInclusionProof<DEPTH>,
        right: OrderedMerkleTreeInclusionProof<DEPTH>,
    ) -> Self {
        Self { left, right }
    }
}

/// Computes the root a leaf hashes up to along its sibling path (Poseidon2, binary tree)
pub fn ordered_mt_compute_root<let DEPTH: u32>(
    inclusion_proof: OrderedMerkleTreeInclusionProof<DEPTH>,
) -> Field {
    let path_in_bits: [bool; DEPTH] = inclusion_proof.leaf_index.to_be_bits::<DEPTH>();

    let mut current = inclusion_proof.leaf;
    for i in 0..DEPTH {
        let (left, right) = if path_in_bits[DEPTH - i - 1] {
            (inclusion_proof.sibling_path[i], current)
        } else {
            (current, inclusion_proof.sibling_path[i])
        };

        current = Poseidon2::hash([left, right], 2);
    }
    current
}

pub fn ordered_mt_verify_inclusion<let DEPTH: u32>(
    root: Field,
    inclusion_proof: OrderedMerkleTreeInclusionProof<DEPTH>,
) {
    assert(ordered_mt_compute_root(inclusion_proof) == root);
}

/// Asserts that `leaf` is not in the ordered tree: the proof gives two leaves adjacent in the
/// tree with `left < leaf < right`. The tree must hold sentinel leaves at both ends.
pub fn ordered_mt_non_membership<let DEPTH: u32>(
    root: Field,
    leaf: Field,
    proof: OrderedMerkleTreeProof<DEPTH>,
) {
    ordered_mt_verify_inclusion(root, proof.left);
    ordered_mt_verify_inclusion(root, proof.right);

    assert(proof.left.leaf.lt(leaf));
    assert(leaf.lt(proof.right.leaf));

    assert(proof.left.leaf_index + 1 == proof.right.leaf_index);
}
