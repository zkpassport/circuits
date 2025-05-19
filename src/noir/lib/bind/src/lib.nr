use std::hash::poseidon2::Poseidon2;
use utils::PROOF_TYPE_BIND;

/// Calculate the commitment of the data and the expected hash using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `data`: The data to bind to
/// * `expected_hash`: The expected hash
///
/// # Returns
///
/// * `commitment`: The commitment of the data and the expected hash
pub fn calculate_param_commitment(data: [Field; 500], expected_hash: Field) -> Field {
    let mut params = [0 as Field; 502];
    params[0] = PROOF_TYPE_BIND as Field;
    for i in 1..501 {
        params[i] = data[i - 1] as Field;
    }
    params[501] = expected_hash;
    Poseidon2::hash(params, 502)
}

/// Calculate the commitment of the data and the expected hash using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `data`: The data to bind to
/// * `expected_hash`: The expected hash
///
/// # Returns
///
/// * `commitment`: The commitment of the data and the expected hash
pub fn calculate_param_commitment_sha2(data: [u8; 500], expected_hash: [u8; 32]) -> Field {
    let mut params = [0 as u8; 533];
    params[0] = PROOF_TYPE_BIND as u8;
    for i in 1..501 {
        params[i] = data[i - 1];
    }
    for i in 501..533 {
        params[i] = expected_hash[i - 501];
    }
    let hash = sha256::sha256_var(params, 533);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
