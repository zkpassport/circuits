use poseidon::poseidon2::Poseidon2;
use utils::constants::PROOF_TYPE_SANCTIONS_EXCLUSION;

global SANCTIONS_PARAM_COMMITMENT_SHA2_SIZE: u32 = 36;

/// Calculate the commitment of the country list using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `root_hash`: Ordered merkle tree root hash
/// * `is_strict`: Whether the strict mode is enabled
pub fn calculate_param_commitment(root_hash: Field, is_strict: bool) -> Field {
    let mut params = [0 as Field; 4];
    params[0] = PROOF_TYPE_SANCTIONS_EXCLUSION as Field;
    params[1] = (params.len() - 2) as Field;
    params[2] = root_hash;
    params[3] = is_strict as Field;
    Poseidon2::hash(params, params.len())
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
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    let root_hash_bytes: [u8; 32] = root_hash.to_be_bytes();
    for i in 3..root_hash_bytes.len() + 3 {
        params[i] = root_hash_bytes[i - 3];
    }
    params[params.len() - 1] = is_strict as u8;
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
