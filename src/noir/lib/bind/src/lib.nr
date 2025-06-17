use std::hash::poseidon2::Poseidon2;
use utils::PROOF_TYPE_BIND;

/// Calculate the commitment of the data using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `data`: The data to bind to
///
/// # Returns
///
/// * `commitment`: The commitment of the data
pub fn calculate_param_commitment(data: [Field; 500]) -> Field {
    let mut params = [0 as Field; 501];
    params[0] = PROOF_TYPE_BIND as Field;
    for i in 1..501 {
        params[i] = data[i - 1] as Field;
    }
    Poseidon2::hash(params, 501)
}

/// Calculate the commitment of the data using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `data`: The data to bind to
///
/// # Returns
///
/// * `commitment`: The commitment of the data
pub fn calculate_param_commitment_sha2(data: [u8; 500]) -> Field {
    let mut params = [0 as u8; 501];
    params[0] = PROOF_TYPE_BIND as u8;
    for i in 1..501 {
        params[i] = data[i - 1];
    }
    let hash = sha256::sha256_var(params, 501);
    utils::packing::pack_be_bytes_into_field::<32, 31>(hash)
}
