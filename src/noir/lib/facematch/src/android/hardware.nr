use super::AndroidKeyDescription;
use super::constants::{
    ANDROID_BOOT_KEY_ALLOWLIST_DEPTH, ANDROID_MAX_OS_PATCH_AGE_MONTHS,
    ANDROID_REVOCATION_TREE_DEPTH, KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    VERIFIED_BOOT_STATE_SELF_SIGNED, VERIFIED_BOOT_STATE_VERIFIED,
};
use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{
    ordered_mt::{
        ordered_mt_compute_root, ordered_mt_non_membership, OrderedMerkleTreeInclusionProof,
        OrderedMerkleTreeProof,
    },
    poseidon2_hash_packed,
};

pub type RevocationProof = OrderedMerkleTreeProof<ANDROID_REVOCATION_TREE_DEPTH>;

/// Asserts that a certificate serial number is not in the tree of revoked attestation
/// certificates. A leaked keybox is revoked by the serial of its attestation certificate.
pub fn assert_serial_not_revoked(revocation_root: Field, serial: Field, proof: RevocationProof) {
    ordered_mt_non_membership(revocation_root, serial, proof);
}

/// Whether a YYYYMM security patch level is at most `ANDROID_MAX_OS_PATCH_AGE_MONTHS` older
/// than `current_date`, and not more than a month ahead of it
pub fn is_os_patch_level_recent(os_patch_level: u32, current_date: u64) -> bool {
    let date = Date::from_timestamp(current_date);
    let patch_year = os_patch_level / 100;
    let patch_month = os_patch_level % 100;
    let patch_months = patch_year * 12 + patch_month;
    let current_months = date.year * 12 + date.month as u32;
    (patch_month >= 1)
        & (patch_month <= 12)
        & (patch_months <= current_months + 1)
        & (current_months <= patch_months + ANDROID_MAX_OS_PATCH_AGE_MONTHS)
}

pub fn get_boot_key_allowlist_leaf(verified_boot_key: [u8; 32]) -> Field {
    poseidon2_hash_packed(verified_boot_key, 32)
}

/// Asserts that key attestation alone vouches for the device: the key lives in a TEE or
/// StrongBox, the bootloader is locked, the OS booted verified, either with the OEM key or
/// with a user-installed key on the allowlist, and the security patch is recent.
pub fn verify_hardware_device_state<let APP_ID_MAX_LEN: u32>(
    key_description: AndroidKeyDescription<APP_ID_MAX_LEN>,
    boot_key_allowlist_root: Field,
    boot_key_index: Field,
    boot_key_path: [Field; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
    current_date: u64,
) {
    assert(
        key_description.attestation_security_level >= KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        "Key attestation must come from a TEE or StrongBox",
    );
    assert(
        key_description.keymint_security_level >= KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        "Attested key must live in a TEE or StrongBox",
    );
    assert(key_description.device_locked, "Bootloader must be locked");
    let state = key_description.verified_boot_state;
    assert(
        (state == VERIFIED_BOOT_STATE_VERIFIED) | (state == VERIFIED_BOOT_STATE_SELF_SIGNED),
        "OS must pass verified boot",
    );
    if state == VERIFIED_BOOT_STATE_SELF_SIGNED {
        let root = ordered_mt_compute_root(
            OrderedMerkleTreeInclusionProof {
                leaf: get_boot_key_allowlist_leaf(key_description.verified_boot_key),
                leaf_index: boot_key_index,
                sibling_path: boot_key_path,
            },
        );
        assert(root == boot_key_allowlist_root, "Verified boot key is not on the allowlist");
    }
    assert(
        is_os_patch_level_recent(key_description.os_patch_level, current_date),
        "Security patch level is too old",
    );
}

/// Stands in for the Play Integrity public key hash in the parameter commitment of a
/// hardware attestation proof: the boot key allowlist and the digest of the APK signing
/// certificate, which together replace what the Play Integrity verdict vouches for
pub fn calculate_hardware_integrity_anchor(
    boot_key_allowlist_root: Field,
    app_signing_digest: [u8; 32],
) -> Field {
    Poseidon2::hash(
        [boot_key_allowlist_root, poseidon2_hash_packed(app_signing_digest, 32)],
        2,
    )
}
