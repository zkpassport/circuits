use poseidon::poseidon2::Poseidon2;
use utils::constants::PROOF_TYPE_SANCTIONS_EXCLUSION;

global SANCTIONS_PARAM_COMMITMENT_SHA2_SIZE: u32 = 34;

/// Calculate the commitment of the country list using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `root_hash`: Ordered merkle tree root hash
/// * `is_strict`: Whether the strict mode is enabled
pub fn calculate_param_commitment(root_hash: Field, is_strict: bool) -> Field {
    let mut params = [0 as Field; 3];
    params[0] = PROOF_TYPE_SANCTIONS_EXCLUSION as Field;
    params[1] = root_hash;
    params[2] = is_strict as Field;
    Poseidon2::hash(params, 3)
}

/// Calculate the commitment of the country list using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `root_hash`: Ordered merkle tree root hash
/// * `is_strict`: Whether the strict mode is enabled
pub fn calculate_param_commitment_sha2(root_hash: Field, is_strict: bool) -> Field {
    let mut params = [0 as u8; SANCTIONS_PARAM_COMMITMENT_SHA2_SIZE];
    params[0] = PROOF_TYPE_SANCTIONS_EXCLUSION;
    let root_hash_bytes: [u8; 32] = root_hash.to_be_bytes();
    for i in 1..root_hash_bytes.len() + 1 {
        params[i] = root_hash_bytes[i - 1];
    }
    params[SANCTIONS_PARAM_COMMITMENT_SHA2_SIZE - 1] = is_strict as u8;
    let hash = sha256::sha256_var(params, SANCTIONS_PARAM_COMMITMENT_SHA2_SIZE as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
