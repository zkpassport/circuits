use poseidon::poseidon2::Poseidon2;
use utils::{
    DisclosedData, DiscloseFlags, get_mrz_from_dg1, ID_CARD_MRZ_BIRTHDATE_INDEX,
    ID_CARD_MRZ_COUNTRY_INDEX, ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX, ID_CARD_MRZ_DOCUMENT_TYPE_INDEX,
    ID_CARD_MRZ_EXPIRY_DATE_INDEX, ID_CARD_MRZ_GENDER_INDEX, ID_CARD_MRZ_LENGTH,
    ID_CARD_MRZ_NAME_INDEX, ID_CARD_MRZ_NATIONALITY_INDEX, IDData, is_id_card,
    PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_COUNTRY_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
    PASSPORT_MRZ_DOCUMENT_TYPE_INDEX, PASSPORT_MRZ_EXPIRY_DATE_INDEX, PASSPORT_MRZ_GENDER_INDEX,
    PASSPORT_MRZ_LENGTH, PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NATIONALITY_INDEX,
    PROOF_TYPE_DISCLOSE,
};

fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        slice[i] = array[start + i];
    }
    slice
}

pub fn get_disclosed_data(dg1: [u8; 95], flags: DiscloseFlags) -> DisclosedData {
    let mrz = get_mrz_from_dg1(dg1);
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

    if is_id_card(dg1) {
        if flags.issuing_country {
            disclosed_data.issuing_country = get_array_slice(
                mrz,
                ID_CARD_MRZ_COUNTRY_INDEX,
                ID_CARD_MRZ_COUNTRY_INDEX + 3,
            );
        }
        if flags.date_of_birth {
            disclosed_data.date_of_birth = get_array_slice(
                mrz,
                ID_CARD_MRZ_BIRTHDATE_INDEX,
                ID_CARD_MRZ_BIRTHDATE_INDEX + 6,
            );
        }
        if flags.nationality {
            disclosed_data.nationality = get_array_slice(
                mrz,
                ID_CARD_MRZ_NATIONALITY_INDEX,
                ID_CARD_MRZ_NATIONALITY_INDEX + 3,
            );
        }
        if flags.name {
            disclosed_data.name =
                get_array_slice(mrz, ID_CARD_MRZ_NAME_INDEX, ID_CARD_MRZ_NAME_INDEX + 30);
        }
        if flags.document_number {
            disclosed_data.document_number = get_array_slice(
                mrz,
                ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
                ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + 9,
            );
        }
        if flags.date_of_expiry {
            disclosed_data.date_of_expiry = get_array_slice(
                mrz,
                ID_CARD_MRZ_EXPIRY_DATE_INDEX,
                ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6,
            );
        }
        if flags.document_type {
            disclosed_data.document_type = get_array_slice(
                mrz,
                ID_CARD_MRZ_DOCUMENT_TYPE_INDEX,
                ID_CARD_MRZ_DOCUMENT_TYPE_INDEX + 2,
            );
        }
        if flags.gender {
            disclosed_data.gender =
                get_array_slice(mrz, ID_CARD_MRZ_GENDER_INDEX, ID_CARD_MRZ_GENDER_INDEX + 1);
        }
    } else {
        if flags.issuing_country {
            disclosed_data.issuing_country = get_array_slice(
                mrz,
                PASSPORT_MRZ_COUNTRY_INDEX,
                PASSPORT_MRZ_COUNTRY_INDEX + 3,
            );
        }
        if flags.date_of_birth {
            disclosed_data.date_of_birth = get_array_slice(
                mrz,
                PASSPORT_MRZ_BIRTHDATE_INDEX,
                PASSPORT_MRZ_BIRTHDATE_INDEX + 6,
            );
        }
        if flags.nationality {
            disclosed_data.nationality = get_array_slice(
                mrz,
                PASSPORT_MRZ_NATIONALITY_INDEX,
                PASSPORT_MRZ_NATIONALITY_INDEX + 3,
            );
        }
        if flags.name {
            disclosed_data.name =
                get_array_slice(mrz, PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NAME_INDEX + 39);
        }
        if flags.document_number {
            disclosed_data.document_number = get_array_slice(
                mrz,
                PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
                PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + 9,
            );
        }
        if flags.date_of_expiry {
            disclosed_data.date_of_expiry = get_array_slice(
                mrz,
                PASSPORT_MRZ_EXPIRY_DATE_INDEX,
                PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6,
            );
        }
        if flags.document_type {
            disclosed_data.document_type = get_array_slice(
                mrz,
                PASSPORT_MRZ_DOCUMENT_TYPE_INDEX,
                PASSPORT_MRZ_DOCUMENT_TYPE_INDEX + 2,
            );
        }
        if flags.gender {
            disclosed_data.gender = get_array_slice(
                mrz,
                PASSPORT_MRZ_GENDER_INDEX,
                PASSPORT_MRZ_GENDER_INDEX + 1,
            );
        }
    }

    disclosed_data
}

pub fn get_disclosed_bytes(dg1: [u8; 95], mask: [u8; 90]) -> [u8; 90] {
    let mut disclosed_bytes = [0 as u8; 90];
    let mrz = get_mrz_from_dg1(dg1);
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
    utils::pack_be_bytes_into_field::<32, 31>(hash)
}
