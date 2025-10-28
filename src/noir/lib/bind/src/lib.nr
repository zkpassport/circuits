use poseidon::poseidon2::Poseidon2;
use utils::constants::PROOF_TYPE_BIND;

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
pub fn calculate_param_commitment(data: [u8; 509]) -> Field {
    let mut params = [0 as Field; 2 + (509 + 30) / 31];
    params[0] = PROOF_TYPE_BIND as Field;
    let packed_data: [Field; (509 + 30) / 31] =
        utils::pack_be_bytes_into_fields::<509, _, 31>(data);
    params[1] = packed_data.len() as Field;
    for i in 2..params.len() {
        params[i] = packed_data[i - 2];
    }
    Poseidon2::hash(params, params.len())
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
pub fn calculate_param_commitment_sha2(data: [u8; 509]) -> Field {
    let mut params = [0 as u8; 512];
    params[0] = PROOF_TYPE_BIND as u8;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(data.len());
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    for i in 3..params.len() {
        params[i] = data[i - 3];
    }
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
