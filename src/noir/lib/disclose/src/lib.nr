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

// Missing tests
// Visually inspected.
// Recommendation: copy this over to `utils/` to avoid duplicated code (replacing the one that's currently there, because this one looks to be more efficient).
// Recommendation: get rid of `end` and call this function with turbofish syntax, if you need to convey the expected return length.
// The function could then be called as:
// - `get_array_slice::<_, M>(arr, start);` or
// - let sliced_arr: [M; u8] = get_arr_slice(arr, start);
fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        slice[i] = array[start + i];
    }
    slice
}


// Apparently this is not used. Consider removing.
pub fn get_disclosed_data(dg1: [u8; 95], flags: DiscloseFlags) -> DisclosedData {
    let mrz = get_mrz_from_dg1(dg1);

    // Recommendation: don't use magic numbers: define globals in `utils/` for these magic number byte-lengths.
    // You could then also write tests to reconcile these globals against the `PASSPORT_MRZ_<NAME>_INDEX` and `ID_CARD_MRZ_<NAME>_INDEX` indices.
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
                ID_CARD_MRZ_COUNTRY_INDEX + 3, // Recommendation: avoid magic numbers (3). (And so on for the rest of this function).
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
        // Danger: If `mask[i]` is NOT being constrained to be only `0` or `1`, then the disclosed bytes can be manipulated!
        // E.g. if `mask[i]` is maliciously set to `2`, then someone can effectively change their birthday or country code etc. by a factor of 2.
        // It's arguably a "critical" bug, but...
        // There's a comment in `bin/disclose/standard/src/main` that the disclosure mask is public, so verifiers can validate the mask.
        // If verifiers do indeed validate that each of the mask bytes is only 0 or 1 (and no other number), then all is fine.
        // If you're leaving it to zkpassport sdk users (i.e. app developers) to write their own verifiers, then this would arguably be too dangerous, as they
        // might forget to constrain the mask bytes to be bools, because this is a very low-level thing to understand.
        // From a quick investigation into the Solidity and Typescript, I can't see any auto-generated verifier code (which might protect sdk users),
        // and I can't see any verifier code that's validating that each mask is 0 or 1.
        // To be extra extra safe, I'd recommend passing the `mask` as a `mask: [bool; 90]` type to `main.nr` instead, 
        // and threading bools through all these functions instead of bytes.
        // Alternatively, you could continue to pass `mask: [u8; 90]` type, as long as you add constraints to assert that these bytes are actually bools (but that feels more brittle).
        // OR, if the intention is to actually be able to do proper masking of individual bits of each passport field (e.g. extracting just the first letter of their name, or extracting just the year of birth),
        // then consider using "more traditional" masking using the `&` operator. But even then, it could be an sdk-user footgun if they're expected to write their own verifier to check the masking is correct.
        disclosed_bytes[i] = mask[i] * mrz[i];
    }
    disclosed_bytes
}

// Inefficient packing. Each byte occupies a Field, instead of packing bytes into fields.
// Possibly several thousand constraints of "wastage".
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
