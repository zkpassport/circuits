use std::hash::poseidon2::Poseidon2;
use utils::dg1::DG1;
use utils::{DisclosedData, DiscloseFlags, PROOF_TYPE_DISCLOSE};
use utils::packing::pack_be_bytes_into_field;

pub fn get_disclosed_data(dg1: DG1, flags: DiscloseFlags) -> DisclosedData {
    let mut disclosed_data = DisclosedData {
        issuing_country: [0 as u8; 3],
        date_of_birth: [0 as u8; 6],
        nationality: [0 as u8; 3],
        name: [0 as u8; 39],
        document_number: [0 as u8; 9],
        date_of_expiry: [0 as u8; 6],
        document_type: [0 as u8; 2],
        gender: [0 as u8; 1],
    };

    if dg1.is_id_card() {
        if flags.issuing_country {
            disclosed_data.issuing_country = dg1.get_issuing_country_id_card();
        }
        if flags.date_of_birth {
            disclosed_data.date_of_birth = dg1.get_date_of_birth_id_card();
        }
        if flags.nationality {
            disclosed_data.nationality = dg1.get_nationality();
        }
        if flags.name {
            disclosed_data.name = dg1.get_name_id_card();
        }
        if flags.document_number {
            disclosed_data.document_number = dg1.get_document_number_id_card();
        }
        if flags.date_of_expiry {
            disclosed_data.date_of_expiry = dg1.get_expiry_date_id_card();
        }
        if flags.document_type {
            disclosed_data.document_type = dg1.get_document_type_id_card();
        }
        if flags.gender {
            disclosed_data.gender = dg1.get_gender_id_card();
        }
    } else {
        if flags.issuing_country {
            disclosed_data.issuing_country = dg1.get_issuing_country_passport();
        }
        if flags.date_of_birth {
            disclosed_data.date_of_birth = dg1.get_date_of_birth_passport();
        }
        if flags.nationality {
            disclosed_data.nationality = dg1.get_nationality_passport();
        }
        if flags.name {
            disclosed_data.name = dg1.get_name_passport();
        }
        if flags.document_number {
            disclosed_data.document_number = dg1.get_document_number_passport();
        }
        if flags.date_of_expiry {
            disclosed_data.date_of_expiry = dg1.get_expiry_date_passport();
        }
        if flags.document_type {
            disclosed_data.document_type = dg1.get_document_type_passport();
        }
        if flags.gender {
            disclosed_data.gender = dg1.get_gender_passport();
        }
    }

    disclosed_data
}

pub fn get_disclosed_bytes(dg1: DG1, mask: [u8; 90]) -> [u8; 90] {
    let mut disclosed_bytes = [0 as u8; 90];
    let mrz = dg1.get_mrz();
    for i in 0..90 {
        disclosed_bytes[i] = mask[i] * mrz[i];
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
    pack_be_bytes_into_field::<32, 31>(hash)
}
