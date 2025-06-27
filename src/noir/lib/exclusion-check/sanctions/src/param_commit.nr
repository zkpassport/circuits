use std::hash::poseidon2::Poseidon2;

global Sanctions_PARAM_COMMITMENT_SIZE: u32 = 33;

/// Calculate the commitment of the country list using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `roots`: Sparse merkle tree roots
///
/// # Returns
///
/// * `commitment`: The commitment of the country list
pub fn calculate_param_commitment(proof_type: u8, root_hash: Field) -> Field {
    let mut params = [0 as Field; Sanctions_PARAM_COMMITMENT_SIZE];
    params[0] = proof_type as Field;
    let root_hash_bytes: [u8; 32] = root_hash.to_be_bytes();
    for i in 1..root_hash_bytes.len() + 1 {
        params[i] = root_hash_bytes[i - 1] as Field;
    }
    Poseidon2::hash(params, Sanctions_PARAM_COMMITMENT_SIZE)
}

pub fn calculate_param_commitment_sha2(proof_type: u8, root_hash: Field) -> Field {
    let mut params = [0 as u8; Sanctions_PARAM_COMMITMENT_SIZE];
    params[0] = proof_type;
    let root_hash_bytes: [u8; 32] = root_hash.to_be_bytes();
    for i in 1..root_hash_bytes.len() + 1 {
        params[i] = root_hash_bytes[i - 1];
    }
    let hash = sha256::sha256_var(params, Sanctions_PARAM_COMMITMENT_SIZE as u64);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}