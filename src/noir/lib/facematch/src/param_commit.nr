use poseidon::poseidon2::Poseidon2;
use utils::constants::PROOF_TYPE_FACEMATCH;

global FACEMATCH_PARAM_COMMITMENT_EVM_BYTES: u32 = 133;

/// The facematch parameter commitment, shared by the iOS and Android face match circuits and the
/// attested ID circuits. `integrity_public_key_hash` and `revocation_root` are 0 on iOS, where
/// there is no Play Integrity key and no published revocation list.
pub fn calculate_param_commitment(
    root_key_leaf: Field,
    environment: u8,
    app_id_hash: Field,
    integrity_public_key_hash: Field,
    facematch_mode: u8,
    revocation_root: Field,
) -> Field {
    let params = [
        PROOF_TYPE_FACEMATCH as Field,
        6,
        root_key_leaf,
        environment as Field,
        app_id_hash,
        integrity_public_key_hash,
        facematch_mode as Field,
        revocation_root,
    ];
    Poseidon2::hash(params, params.len())
}

pub fn calculate_param_commitment_sha2(
    root_key_leaf: Field,
    environment: u8,
    app_id_hash: Field,
    integrity_public_key_hash: Field,
    facematch_mode: u8,
    revocation_root: Field,
) -> Field {
    let mut params = [0 as u8; FACEMATCH_PARAM_COMMITMENT_EVM_BYTES];
    params[0] = PROOF_TYPE_FACEMATCH;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    let mut base_offset = 3;
    let root_key_leaf_bytes: [u8; 32] = root_key_leaf.to_be_bytes();
    for i in 0..32 {
        params[base_offset + i] = root_key_leaf_bytes[i];
    }
    base_offset += 32;
    params[base_offset] = environment;
    base_offset += 1;
    let app_id_hash_bytes: [u8; 32] = app_id_hash.to_be_bytes();
    for i in 0..32 {
        params[base_offset + i] = app_id_hash_bytes[i];
    }
    base_offset += 32;
    let integrity_public_key_hash_bytes: [u8; 32] = integrity_public_key_hash.to_be_bytes();
    for i in 0..32 {
        params[base_offset + i] = integrity_public_key_hash_bytes[i];
    }
    base_offset += 32;
    params[base_offset] = facematch_mode;
    base_offset += 1;
    let revocation_root_bytes: [u8; 32] = revocation_root.to_be_bytes();
    for i in 0..32 {
        params[base_offset + i] = revocation_root_bytes[i];
    }
    let hash = sha256::sha256_var(params, FACEMATCH_PARAM_COMMITMENT_EVM_BYTES);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
