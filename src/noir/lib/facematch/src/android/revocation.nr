use super::constants::ANDROID_REVOCATION_TREE_DEPTH;
use utils::ordered_mt::{ordered_mt_non_membership, OrderedMerkleTreeProof};

pub type RevocationProof = OrderedMerkleTreeProof<ANDROID_REVOCATION_TREE_DEPTH>;

/// Asserts that a certificate serial number is not in the tree of revoked attestation
/// certificates. A leaked keybox is revoked by the serial of its attestation certificate.
pub fn assert_serial_not_revoked(revocation_root: Field, serial: Field, proof: RevocationProof) {
    ordered_mt_non_membership(revocation_root, serial, proof);
}
