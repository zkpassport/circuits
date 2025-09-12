use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{
        ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_COUNTRY_INDEX, ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
        ID_CARD_MRZ_DOCUMENT_TYPE_INDEX, ID_CARD_MRZ_EXPIRY_DATE_INDEX, ID_CARD_MRZ_GENDER_INDEX,
        ID_CARD_MRZ_NAME_INDEX, ID_CARD_MRZ_NATIONALITY_INDEX, PASSPORT_MRZ_BIRTHDATE_INDEX,
        PASSPORT_MRZ_COUNTRY_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
        PASSPORT_MRZ_DOCUMENT_TYPE_INDEX, PASSPORT_MRZ_EXPIRY_DATE_INDEX, PASSPORT_MRZ_GENDER_INDEX,
        PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NATIONALITY_INDEX, PROOF_TYPE_DISCLOSE,
    },
    get_mrz_from_dg1,
    is_id_card,
};

pub mod tests;

pub fn get_disclosed_bytes(dg1: [u8; 95], mask: [u1; 90]) -> [u8; 90] {
    let mut disclosed_bytes = [0 as u8; 90];
    let mrz = get_mrz_from_dg1(dg1);
    for i in 0..90 {
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
pub fn calculate_param_commitment(disclose_mask: [u8; 90], disclosed_bytes: [u8; 90]) -> Field {
    let mut params = [0 as Field; 181];
    params[0] = PROOF_TYPE_DISCLOSE as Field;
    for i in 1..91 {
        params[i] = disclose_mask[i - 1] as Field;
    }
    for i in 91..181 {
        params[i] = disclosed_bytes[i - 91] as Field;
    }
    Poseidon2::hash(params, 181)
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
    disclose_mask: [u8; 90],
    disclosed_bytes: [u8; 90],
) -> Field {
    let mut params = [0 as u8; 181];
    params[0] = PROOF_TYPE_DISCLOSE;
    for i in 1..91 {
        params[i] = disclose_mask[i - 1];
    }
    for i in 91..181 {
        params[i] = disclosed_bytes[i - 91];
    }
    let hash = sha256::sha256_var(params, 181);
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
