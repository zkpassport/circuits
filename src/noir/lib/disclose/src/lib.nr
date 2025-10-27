use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{MAX_MRZ_LENGTH, PROOF_TYPE_DISCLOSE},
    get_mrz_from_dg1,
    types::{DG1Data, DiscloseMask, MRZData},
};

pub mod tests;

pub fn get_disclosed_bytes(dg1: DG1Data, mask: DiscloseMask) -> MRZData {
    let mut disclosed_bytes = [0 as u8; MAX_MRZ_LENGTH];
    let mrz = get_mrz_from_dg1(dg1);
    for i in 0..MAX_MRZ_LENGTH {
        disclosed_bytes[i] = mask[i] as u8 * mrz[i];
    }
    disclosed_bytes
}

/// Calculate the commitment of the disclose mask and disclosed bytes using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `disclose_mask`: The disclose mask
/// * `disclosed_bytes`: The disclosed bytes
///
/// # Returns
///
/// * `commitment`: The commitment of the disclose mask and disclosed bytes
pub fn calculate_param_commitment(disclose_mask: DiscloseMask, disclosed_bytes: MRZData) -> Field {
    let mut params = [0 as Field; MAX_MRZ_LENGTH * 2 + 2];
    params[0] = PROOF_TYPE_DISCLOSE as Field;
    params[1] = (params.len() - 2) as Field;
    // TODO: pack these bytes into fields
    for i in 2..MAX_MRZ_LENGTH + 2 {
        params[i] = disclose_mask[i - 2] as Field;
    }
    for i in MAX_MRZ_LENGTH + 2..MAX_MRZ_LENGTH * 2 + 2 {
        params[i] = disclosed_bytes[i - MAX_MRZ_LENGTH - 2] as Field;
    }
    Poseidon2::hash(params, params.len())
}

/// Calculate the commitment of the disclose mask and disclosed bytes using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `disclose_mask`: The disclose mask
/// * `disclosed_bytes`: The disclosed bytes
///
/// # Returns
///
/// * `commitment`: The commitment of the disclose mask and disclosed bytes
pub fn calculate_param_commitment_sha2(
    disclose_mask: DiscloseMask,
    disclosed_bytes: MRZData,
) -> Field {
    let mut params = [0 as u8; MAX_MRZ_LENGTH * 2 + 3];
    params[0] = PROOF_TYPE_DISCLOSE;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    for i in 3..MAX_MRZ_LENGTH + 3 {
        params[i] = disclose_mask[i - 3] as u8;
    }
    for i in MAX_MRZ_LENGTH + 3..MAX_MRZ_LENGTH * 2 + 3 {
        params[i] = disclosed_bytes[i - MAX_MRZ_LENGTH - 3];
    }
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
