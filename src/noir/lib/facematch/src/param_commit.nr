use poseidon::poseidon2::Poseidon2;
use utils::constants::PROOF_TYPE_FACEMATCH;

global FACEMATCH_PARAM_COMMITMENT_EVM_BYTES: u32 = 67;

pub fn calculate_param_commitment(
    root_key_leaf: Field,
    environment: u8,
    app_id: Field,
    facematch_mode: u8,
) -> Field {
    let params = [
        PROOF_TYPE_FACEMATCH as Field,
        root_key_leaf,
        environment as Field,
        app_id,
        facematch_mode as Field,
    ];
    Poseidon2::hash(params, params.len())
}

pub fn calculate_param_commitment_sha2(
    root_key_leaf: Field,
    environment: u8,
    app_id: Field,
    facematch_mode: u8,
) -> Field {
    let mut params = [0 as u8; FACEMATCH_PARAM_COMMITMENT_EVM_BYTES];
    params[0] = PROOF_TYPE_FACEMATCH;
    let root_key_leaf_bytes: [u8; 32] = root_key_leaf.to_be_bytes();
    for i in 0..root_key_leaf_bytes.len() {
        params[i + 1] = root_key_leaf_bytes[i];
    }
    params[33] = environment;
    let app_id_bytes: [u8; 32] = app_id.to_be_bytes();
    for i in 0..app_id_bytes.len() {
        params[i + 34] = app_id_bytes[i];
    }
    params[66] = facematch_mode;

    let hash = sha256::sha256_var(params, FACEMATCH_PARAM_COMMITMENT_EVM_BYTES as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
