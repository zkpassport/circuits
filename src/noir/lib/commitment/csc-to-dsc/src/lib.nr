use common::{
    calculate_certificate_root_v1, CertificateTreeLeaf,
    compute_certificate_tree_root_using_hash_path_v1, CSC_CERT_TYPE, hash_salt_country_tbs,
};
use utils::types::Alpha3CountryCode;

/*
# Sub-circuit A: CSC to DSC
# Verifies the CSCA signed the DSC, and the CSCA certificate is in the Certificate Registry
# under the published v1 certificate_registry_root.
#
#   state_root                = Poseidon2(certificate_tree_root, revocation_tree_root, masterlist_tree_root)
#   certificate_registry_root = Poseidon2(packed(schema_version[u16 BE] || timestamp[u32 BE]), state_root)
#
# The revocation and masterlist tree roots are bound to the published `certificate_registry_root`
# via the hash above, but their CONTENTS are not consulted anywhere in the four-stage pipeline:
#   - revocation_tree_root: the per-DSC revocation set (leaf = H(csc_fingerprint, H(dsc_serial))).
#     Its non-membership is NOT proven, so a revoked DSC would still verify once the registry
#     starts publishing revocations. See the interim tripwire + TODO below.
#   - masterlist_tree_root: ICAO master-list *file* hashes (provenance/transparency metadata,
#     not per-certificate data), so there is intentionally nothing to check it against here.
*/

// Root of an empty revocation Merkle tree (height 14, zero-value 0, Poseidon2 arity 2), as
// produced by @zkpassport/utils `buildMerkleTreeFromRevocations([])`. The live mainnet
// registry publishes no revocations, so this is the value hashed into the on-chain
// certificate_registry_root today (verified: recomputing the published root with an empty
// revocation tree reproduces the on-chain root exactly).
global EMPTY_REVOCATION_TREE_ROOT: Field =
    0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a;
pub fn commit_to_dsc<let CSC_KEY_SIZE: u32, let HASH_PATH_SIZE: u32, let TBS_CERT_SIZE: u32>(
    certificate_registry_root: Field,
    schema_version: u16,
    timestamp: u32,
    certificate_tree_index: Field,
    certificate_tree_hash_path: [Field; HASH_PATH_SIZE],
    certificate_tags: [Field; 3],
    country: Alpha3CountryCode,
    tbs_certificate: [u8; TBS_CERT_SIZE],
    salt: Field,
    csc_pubkey: [u8; CSC_KEY_SIZE],
    csc_expiry: u32,
    csc_fingerprint: Field,
    revocation_tree_root: Field,
    masterlist_tree_root: Field,
) -> Field {
    // Verify the CSCA exists in the certificate tree and recover the cert tree root.
    let leaf = CertificateTreeLeaf {
        tags: certificate_tags,
        cert_type: CSC_CERT_TYPE,
        country,
        public_key: csc_pubkey,
        expiry: csc_expiry,
        fingerprint: csc_fingerprint,
    };
    let certificate_tree_root = compute_certificate_tree_root_using_hash_path_v1(
        leaf,
        certificate_tree_index,
        certificate_tree_hash_path,
    );
    // Reconstruct the published v1 certificate registry root and assert it matches the public input.
    let computed_root = calculate_certificate_root_v1(
        schema_version,
        timestamp,
        certificate_tree_root,
        revocation_tree_root,
        masterlist_tree_root,
    );
    assert(computed_root == certificate_registry_root, "Certificate registry root mismatch");

    // Interim revocation tripwire: the registry currently publishes an empty revocation
    // tree, and this sub-circuit does not yet enforce per-DSC non-revocation. Asserting the
    // empty-tree root here is a no-op for every proof today, but turns the first published
    // revocation into a hard failure instead of silently accepting a revoked DSC.
    //
    // TODO(revocation): replace this assert with a real ordered-Merkle NON-membership proof
    // of H(csc_fingerprint, H(dsc_serial)) against `revocation_tree_root`. That requires
    // extracting the DSC serial from `tbs_certificate` and threading a prover-supplied
    // exclusion witness (new input -> signature change -> bin regeneration), plus wiring
    // `buildRevocationExclusionProof` on the @zkpassport/utils side. Until resolved,
    // do NOT start publishing revocations without landing that check first - this assert is
    // the guard that enforces it.
    assert(
        revocation_tree_root == EMPTY_REVOCATION_TREE_ROOT,
        "Revocation tree is non-empty but in-circuit non-revocation is not yet enforced",
    );

    // Output commitment glue
    let comm_out = hash_salt_country_tbs(salt, country, tbs_certificate);
    comm_out
}
