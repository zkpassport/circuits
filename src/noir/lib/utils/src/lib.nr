/**
* The standards for passports and any other travel documents, electronic or not,
* are defined in the ICAO (International Civil Aviation Organization) 9303 document available here:
* https://www.icao.int/publications/pages/publication.aspx?docnum=9303
*/
pub mod tests;
pub mod types;

/**
* The structure of the MRZ is well defined and standardized by the ICAO
* so the index will always be the same for every passport
* c.f. ICAO 9303-4, Appendix B
*/

// The following constants define the indices of the information
// we need to generate various proofs of identity from the MRZ
// The structure of the MRZ is slightly different between passports
// and ID cards so we need to define indices for both types

use types::{
    DG1Data, MRZData, MRZName, MRZDOB, MRZYOB, MRZDocumentNumber, MRZNationality, MRZIssuingCountry,
};

// Consider creating a dedicated constants.nr file for all these globals.

// Index for the country of issuance of the passport
pub global PASSPORT_MRZ_COUNTRY_INDEX: u32 = 2; // Consider renaming to "PASSPORT_MRZ_ISSUING_COUNTRY_INDEX"
// Length of the country code in the MRZ
pub global PASSPORT_MRZ_COUNTRY_LENGTH: u32 = 3;
// Index for the three letter code of the country of citizenship
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global PASSPORT_MRZ_NATIONALITY_INDEX: u32 = 54;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global PASSPORT_MRZ_GENDER_INDEX: u32 = 64;
// Index for the date of expiry (YYMMDD)
pub global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;
// Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
pub global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;
// Length of the date of birth in the MRZ
pub global PASSPORT_MRZ_BIRTHDATE_LENGTH: u32 = 6;
// Length of the year of birth in the MRZ
pub global PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;
// Index for the document number in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 44;
// Length of the document number in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;
// Index for the document type in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global PASSPORT_MRZ_NAME_INDEX: u32 = 5;
// Length of the name of the passport holder
pub global PASSPORT_MRZ_NAME_LENGTH: u32 = 39;
// Length of the MRZ on a passport
pub global PASSPORT_MRZ_LENGTH: u32 = 88;

// Index for the country of issuance of the ID card
pub global ID_CARD_MRZ_COUNTRY_INDEX: u32 = 2;
// Length of the country code in the MRZ
pub global ID_CARD_MRZ_COUNTRY_LENGTH: u32 = 3;
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global ID_CARD_MRZ_NATIONALITY_INDEX: u32 = 45;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global ID_CARD_MRZ_GENDER_INDEX: u32 = 37;
// Index for the date of expiry (YYMMDD)
pub global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;
// Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
pub global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;
// Length of the date of birth in the MRZ
pub global ID_CARD_MRZ_BIRTHDATE_LENGTH: u32 = 6;
// Length of the year of birth in the MRZ
pub global ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH: u32 = 2;
// Index for the document number in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 5;
// Length of the document number in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH: u32 = 9;
// Index for the document type in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global ID_CARD_MRZ_NAME_INDEX: u32 = 60;
/// Length for the MRZ on an ID card
pub global ID_CARD_MRZ_NAME_LENGTH: u32 = 30;
// Length of the MRZ on an ID card
pub global ID_CARD_MRZ_LENGTH: u32 = 90;

// ASCII_CODE FOR <
pub global ASCII_CODE_FOR_LESS_THAN: u8 = 60;

/// Offset of the MRZ in the DG1
pub global DG1_TO_MRZ_OFFSET: u32 = 5;

// ECDSA curves mapping
pub global ECDSA_CURVE_P256: u32 = 0;
pub global ECDSA_CURVE_P384: u32 = 1;
pub global ECDSA_CURVE_P521: u32 = 2;
pub global ECDSA_CURVE_BRAINPOOL_B256R1: u32 = 3;
pub global ECDSA_CURVE_BRAINPOOL_B256T1: u32 = 4;
pub global ECDSA_CURVE_BRAINPOOL_B384R1: u32 = 5;
pub global ECDSA_CURVE_BRAINPOOL_B384T1: u32 = 6;
pub global ECDSA_CURVE_BRAINPOOL_B512R1: u32 = 7;
pub global ECDSA_CURVE_BRAINPOOL_B512T1: u32 = 8;

// Proof type to identify the circuit used for a given parameter commitment
pub global PROOF_TYPE_DISCLOSE: u8 = 0;
pub global PROOF_TYPE_AGE: u8 = 1;
pub global PROOF_TYPE_BIRTHDATE: u8 = 2;
pub global PROOF_TYPE_EXPIRY_DATE: u8 = 3;
pub global PROOF_TYPE_NATIONALITY_INCLUSION: u8 = 4;
pub global PROOF_TYPE_NATIONALITY_EXCLUSION: u8 = 5;
pub global PROOF_TYPE_ISSUING_COUNTRY_INCLUSION: u8 = 6;
pub global PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION: u8 = 7;
pub global PROOF_TYPE_BIND: u8 = 8;
pub global PROOF_TYPE_SANCTIONS_EXCLUSION: u8 = 9;

// D<<
global GERMANY_PASSPORT_CODE: [u8; 3] = [68, 60, 60];
// DEU
global GERMANY_ISO_CODE: [u8; 3] = [68, 69, 85];

pub struct IDData {
    // Regroups the hashes of all the data groups plus some padding
    // at the start and in between each data group hashes
    pub e_content: [u8; 700],
    pub e_content_size: u32,
    // Where we can find e_content in the signed_attributes
    // It varies from document to document according to the length
    // of the padding at the start
    pub dg1_offset_in_e_content: u32,
    // Last 32 bytes: result of the hash of all the hashes of the data groups
    // Rest of the bytes: information about the signature algorithm, date, etc.
    pub signed_attributes: [u8; 200],
    pub signed_attributes_size: u32,
    // The DG1 contains the Machine Readable Zone (MRZ) of the document
    // The two lines at the bottom of the passport data page
    // or the three bottom lines on the rear of an ID card
    // 95 bytes for passports, 93 bytes for ID cards
    // Including 88 bytes of MRZ and 5 bytes of padding for passports
    // and 90 bytes of MRZ and 5 bytes of padding for ID cards
    pub dg1: DG1Data,
    // The signature over the data groups
    pub sod_signature: [u8; 512],
    pub sod_signature_size: u32,
}

pub struct DSCData {
    // The TBS certificate of the DSC
    // TBS stands for To Be Signed
    pub tbs_certificate: [u8; 1500],
    pub tbs_certificate_size: u32,
    // The public key of the DSC (up to 512 bytes to account for RSA-4096)
    pub pubkey: [u8; 512],
    // The actual size of the public key
    pub pubkey_size: u32,
    // The index of the public key in the TBS certificate
    pub pubkey_index: u32,
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    pub pubkey_redc_param: [u8; 513],
    // The signature over the TBS certificate
    pub signature: [u8; 512],
    pub signature_size: u32,
    // The exponent of the public key
    // Only useful for RSA, can be ignored for ECDSA
    pub exponent: u32,
}

pub struct CSCData {
    // The public key of the CSC (up to 512 bytes to account for RSA-4096)
    pub pubkey: [u8; 512],
    // The actual size of the public key
    pub pubkey_size: u32,
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    pub pubkey_redc_param: [u8; 513],
    // Only useful for RSA, can be ignored for ECDSA
    pub exponent: u32,
}

pub struct DiscloseFlags {
    pub issuing_country: bool,
    pub nationality: bool,
    pub document_type: bool,
    pub document_number: bool,
    pub date_of_expiry: bool,
    pub date_of_birth: bool,
    pub gender: bool,
    pub name: bool,
}

pub struct DisclosedData {
    pub issuing_country: [u8; 3],
    pub nationality: [u8; 3],
    pub document_type: [u8; 2],
    pub document_number: [u8; 9],
    pub date_of_expiry: [u8; 6],
    pub date_of_birth: [u8; 6],
    pub name: [u8; 39],
    pub gender: [u8; 1],
}

// Missing tests
// Visually inspected.
// `end` is not technically needed, if it's always anticipated that `end - start == M`.
// In fact, for safety, consider removing end, (or at least static_asserting that `end - start == M`).
// The function could then be called as:
// - `get_array_slice::<_, M>(arr, start);` or
// - let sliced_arr: [M; u8] = get_arr_slice(arr, start);
pub fn get_array_slice<let N: u32, let M: u32>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        // Avoid writing to a dynamic index (relatively expensive): it's cheaper to _read_ from a dynamic index.
        // Consider using the implementation in `disclose/src/lib.nr`
        slice[i - start] = arr[i];
    }
    slice
}

// Not used. Not checked. Consider removing.
pub fn get_array_slice_constant<let N: u32, let M: u32>(arr: [u8; N]) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        slice[i] = arr[i];
    }
    slice
}

// Not used. Not checked. Consider removing.
// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

// Not used. Not checked. Consider removing.
pub fn insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
) -> [u8; N] {
    for i in index..index + M {
        arr[i] = sub_arr[i - index];
    }
    arr
}

// Not used. Not checked. Consider removing.
pub fn dynamic_insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
    max_size: u32,
) -> [u8; N] {
    for i in index..index + max_size {
        if i - index < M {
            arr[i] = sub_arr[i - index];
        }
    }
    arr
}

// Visually inspected.
pub fn is_id_card(dg1: DG1Data) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[93] != 0) & (dg1[94] != 0)
}

// Missing Tests.
// Consider renaming MAX_FIELD_SIZE -> MAX_FIELD_SIZE_IN_BYTES.
// Consider adding std::static_assert(MAX_FIELD_SIZE <= 31, "..."); - Edit: I just saw in the bind circuit (and all `calculate_param_commitment_sha2` functions) that sometimes you want a 32-byte input to be truncated to 31 bytes to fit within a field. Consider adding a dedicated "unsafe" variant of this function so that it's clear when you're willing to allow truncation. E.g. it's likely alright to truncate a byte from the output of a sha256 function (as is done in the bind circuit), but it wouldn't be alright to accidentally truncate a byte from raw data.
// Consider adding std::static_assert(NBytes <= MAX_FIELD_SIZE, "...");
pub fn pack_be_bytes_into_field<let NBytes: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> Field {
    let mut result: Field = 0;
    for i in 0..MAX_FIELD_SIZE {
        result *= 256;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

// Visually inspected.
// Consider adding more test cases for the various numeric generics that are 
// actually used within the zkpassport circuits.
// Consider renaming MAX_FIELD_SIZE -> MAX_FIELD_SIZE_IN_BYTES.
// Consider adding std::static_assert(NBytes <= MAX_FIELD_SIZE, "...");
// Consider adding std::static_assert(MAX_FIELD_SIZE <= 31, "...");
pub fn pack_be_bytes_into_u128s<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> [u128; N] {
    let mut result = [0 as u128; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb as u128;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb as u128;
    }

    result
}

// Visually inspected.
// Consider adding more test cases for the various numeric generics that are 
// actually used within the zkpassport circuits.
// Consider renaming MAX_FIELD_SIZE -> MAX_FIELD_SIZE_IN_BYTES or MAX_BYTES_PER_FIELD
// Consider adding std::static_assert(NBytes <= MAX_FIELD_SIZE, "...");
// Consider adding std::static_assert(MAX_FIELD_SIZE <= 31, "...");
// Consider adding std::static_assert((NBytes + MAX_FIELD_SIZE - 1) / MAX_FIELD_SIZE > N); to ensure N is large enough to not accidentally truncate the output. (although the `MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes` for-loop-bound might achieve this... but I'm not sure if Noir would throw an error for too-small an N, or whether it would just silently skip the loop and truncate the output).
pub fn pack_be_bytes_into_fields<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> [Field; N] {
    let mut result = [0 as Field; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb;
    }

    result
}

// Missing tests.
// Visually inspected.
// Consider establishing globals for `95` and `90`, and using them throughout the codebase for DG1_LEN and MRZ_LEN.
pub fn get_mrz_from_dg1(dg1: DG1Data) -> MRZData {
    let mut mrz: MRZData = [0 as u8; 90];
    for i in 0..90 {
        mrz[i] = dg1[i + DG1_TO_MRZ_OFFSET];
    }
    mrz
}

// Missing tests.
// Visually inspected.
// Note: this only works for an array of even length.
pub fn split_array<let N: u32>(array: [u8; N * 2]) -> ([u8; N], [u8; N]) {
    let mut array_x = [0 as u8; N];
    let mut array_y = [0 as u8; N];
    for i in 0..N {
        array_x[i] = array[i];
        array_y[i] = array[i + N];
    }
    (array_x, array_y)
}

// Missing tests.
// Recommend using Noir's native array .concat() method, which has been tested.
pub fn concat_array<let N: u32>(array_x: [u8; N], array_y: [u8; N]) -> [u8; N * 2] {
    let mut array = [0 as u8; N * 2];
    for i in 0..N {
        array[i] = array_x[i];
        array[i + N] = array_y[i];
    }
    array
}

// Missing tests.
// Suggestion: The output of this function seems to always be hashed. 
// This approach to packing (1 byte into 1 field) is very inefficient, and will result in more hashing
// constraints than necessary. Consider more-tightly packing the data before hashing.
/**
 * Concatenate two arrays (of different sizes) into one array
 */
pub fn array_concat_as_field<let N: u32, let M: u32>(
    array1: [u8; N],
    array2: [u8; M],
) -> [Field; N + M] {
    let mut result = [0 as Field; N + M];
    for i in 0..N {
        result[i] = array1[i] as Field;
    }
    for i in 0..M {
        result[N + i] = array2[i] as Field;
    }
    result
}

// Not used. Not checked. Consider removing.
// Inconsistent leading underscore. Consider removing `_`, or aligning all unconstrained functions to 
// have such a leading underscore.
pub unconstrained fn _find_subarray_index<let N: u32, let M: u32>(
    array: [u8; N],
    subarray: [u8; M],
) -> u32 {
    let mut index = 0;
    for i in 0..(N - M + 1) {
        let mut found = true;
        for j in 0..M {
            if array[i + j] != subarray[j] {
                found = false;
                break;
            }
        }
        if found {
            index = i;
            break;
        }
    }
    index
}

// Missing tests.
// Visually inspected.
// Potential optimisation (sometimes this marginally improves constraints vs using an inequality `>=` inside a loop):
// let mut hit_len = false;
// for i in 0..N {
//     if i == len {
//         hit_len = true
//     }
//     if hit_len {
//         assert_eq(padded_array[i], T::default());
//     }
// }
pub fn check_zero_padding<let N: u32, T>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            // This presumes `default()` has similar meaning to `zeroed`, which wont be true for all types T. Consider using `std::mem::zeroed();`, or concrete types (like `u8`) instead of T.
            assert_eq(padded_array[i], T::default());
        }
    }
}

// Missing Tests.
// Visually inspected, with the assumption that the global constants are correct.
// Potential optimisation:
// Establish the `start` and `end` indices as variables, and then only 
// call `get_array_slice` once (rather than the two times currently).
// Having said that, I _think_ the calls to `get_array_slice` might evaluate at
// comptime, because you're passing global constants in as args. So maybe this
// is optimal.
pub fn get_nationality_from_mrz(dg1: DG1Data) -> MRZNationality {
    let mrz = get_mrz_from_dg1(dg1);

    let mut country_bytes: MRZNationality = [0; 3];

    if is_id_card(dg1) {
        country_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_NATIONALITY_INDEX,
            ID_CARD_MRZ_NATIONALITY_INDEX + ID_CARD_MRZ_COUNTRY_LENGTH,
        );
    } else {
        country_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_NATIONALITY_INDEX,
            PASSPORT_MRZ_NATIONALITY_INDEX + PASSPORT_MRZ_COUNTRY_LENGTH,
        );
    }

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}

// Missing Tests.
// Visually inspected, with the assumption that the global constants are correct.
pub fn get_issuing_country_from_mrz(dg1: DG1Data) -> MRZIssuingCountry {
    let mrz = get_mrz_from_dg1(dg1);
    // No need to check if it's an ID card since the issuing country
    // is always at the same index for both passports and ID cards
    // Suggestion:
    // `std::static_assert(PASSPORT_MRX_COUNTRY_INDEX == ID_CARD_MRZ_COUNTRY_INDEX, "Country index mismatch");`
    // `std::static_assert(PASSPORT_MRZ_COUNTRY_LENGTH == PASSPORT_MRZ_COUNTRY_LENGTH, "Country length mismatch");`
    let mut country_bytes = get_array_slice(
        mrz,
        PASSPORT_MRZ_COUNTRY_INDEX,
        PASSPORT_MRZ_COUNTRY_INDEX + PASSPORT_MRZ_COUNTRY_LENGTH,
    );

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}


//***********************************************************************


// Visually inspected.
/// Get the name from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_name_from_mrz(dg1: DG1Data) -> MRZName {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_name_id_card(mrz)
    } else {
        get_name_passport(mrz)
    }
}

// Visually inspected.
/// Get the name from the MRZ for a passport
pub fn get_name_passport(mrz: MRZData) -> MRZName {
    get_array_slice(
        mrz,
        PASSPORT_MRZ_NAME_INDEX,
        PASSPORT_MRZ_NAME_INDEX + PASSPORT_MRZ_NAME_LENGTH,
    )
}

// Visually inspected.
/// Get the name from the MRZ for an ID card
pub fn get_name_id_card(mrz: MRZData) -> MRZName {
    let mut mrz_name: MRZName = get_array_slice(
        mrz,
        ID_CARD_MRZ_NAME_INDEX,
        ID_CARD_MRZ_NAME_INDEX + ID_CARD_MRZ_NAME_LENGTH,
    );

    // Pad the name with spaces to the length of the MRZ name
    for i in 0..(PASSPORT_MRZ_NAME_LENGTH - ID_CARD_MRZ_NAME_LENGTH) {
        mrz_name[ID_CARD_MRZ_NAME_LENGTH + i] = ASCII_CODE_FOR_LESS_THAN;
    }

    mrz_name
}

// Missing Tests.
// Visually inspected.
/// Get the date of birth from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_dob_from_mrz(dg1: DG1Data) -> MRZDOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_date_of_birth_id_card(mrz)
    } else {
        get_date_of_birth_passport(mrz)
    }
}

// Missing Tests.
// Visually inspected.
/// Get the date of birth from the MRZ for a passport
pub fn get_date_of_birth_passport(mrz: MRZData) -> MRZDOB {
    get_array_slice(
        mrz,
        PASSPORT_MRZ_BIRTHDATE_INDEX,
        PASSPORT_MRZ_BIRTHDATE_INDEX + PASSPORT_MRZ_BIRTHDATE_LENGTH,
    )
}

// Missing Tests.
// Visually inspected.
/// Get the date of birth from the MRZ for an ID card
pub fn get_date_of_birth_id_card(mrz: MRZData) -> MRZDOB {
    get_array_slice(
        mrz,
        ID_CARD_MRZ_BIRTHDATE_INDEX,
        ID_CARD_MRZ_BIRTHDATE_INDEX + ID_CARD_MRZ_BIRTHDATE_LENGTH,
    )
}

// Missing Tests.
// Visually inspected.
/// Get the year of birth from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_yob_from_mrz(dg1: DG1Data) -> MRZYOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_yob_from_mrz_id_card(mrz)
    } else {
        get_yob_from_mrz_passport(mrz)
    }
}

// Missing Tests.
// Visually inspected.
/// Get the year of birth from the MRZ for an ID card
pub fn get_yob_from_mrz_passport(mrz: MRZData) -> MRZYOB {
    get_array_slice(
        mrz,
        PASSPORT_MRZ_BIRTHDATE_INDEX,
        PASSPORT_MRZ_BIRTHDATE_INDEX + PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH,
    )
}

// Missing Tests.
// Visually inspected.
/// Get the year of birth from the MRZ for an ID card
pub fn get_yob_from_mrz_id_card(mrz: MRZData) -> MRZYOB {
    get_array_slice(
        mrz,
        ID_CARD_MRZ_BIRTHDATE_INDEX,
        ID_CARD_MRZ_BIRTHDATE_INDEX + ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH,
    )
}

// Missing Tests.
// Visually inspected.
/// Get the document number from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_document_number_from_mrz(dg1: DG1Data) -> MRZDocumentNumber {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_document_number_id_card(mrz)
    } else {
        get_document_number_passport(mrz)
    }
}

// Missing Tests.
// Visually inspected.
/// Get the document number from the MRZ for a passport
pub fn get_document_number_passport(mrz: MRZData) -> MRZDocumentNumber {
    get_array_slice(
        mrz,
        PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
        PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH,
    )
}

// Missing Tests.
// Visually inspected.
/// Get the document number from the MRZ for an ID card
pub fn get_document_number_id_card(mrz: MRZData) -> MRZDocumentNumber {
    get_array_slice(
        mrz,
        ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
        ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH,
    )
}

// TO CHECK (in the constrained code):
// Is the class (bits 6 & 7) and the form (bit 5) being checked to match the
// expectations of passport encodings?
// This code accepts non-DER encodings (e.g. length 0x81 0x05 instead of 0x05). Is that ok? My reading suggests it's not ok, and passports prefer unambiguous encodings (DER).
// I.e. it is not strict to DER rules - is that ok?
// Do you want to allow "null" = 0x05 0x00? It is currently allowed.

/// Returns total TLV length (tag + length field + content) for any
/// ASN.1 element using DER/BER **definite-length** encoding with a
/// single-byte tag (tag number field < 31)
///
pub unconstrained fn unsafe_get_asn1_element_length<let N: u32>(asn1: [u8; N]) -> u32 {
    let tag: u8 = asn1[0];
    let elem_len: u8 = asn1[1];

    /*
     * Tag encoding:
     * 
     * | 7 6 | 5 | 4 3 2 1 0 | <- bit index
     * |     |   |           | <- bits
     *    ^    ^      ^
     *    |    |      |
     *    |    |     Tag - a number < 31 (so 11111 is not allowed).
     *    |    |
     *    |   Form: 0=primitive type, 1=constructed type
     *    |
     *  class: 00=universal, 01=application, 10=context-specific, 11=private
     */

    /*
     * Length encoding ("short form"):
     * 
     * | 7 | 6 5 4 3 2 1 0 | <- bit index
     * | 0 |  L e n g t h  | <- bits
     *   ^        ^
     *   |        |
     *   |       Length - a number between 0 - 127 (inclusive)
     *   |  
     *  delineates that this is the "short form" encoding.
     *
     * Length encoding ("short form"):
     * 
     * | 7 | 6 5 4 3 2 1 0 | 7 6 5 4 3 2 1 0 | ... | 7 6 5 4 3 2 1 0 | <- bit index
     * | 1 |               | L e n g t h   N | ... | L e n g t h   1 | <- bits
     *   ^        ^
     *   |        |
     *   |       Length of the length (not 0), in bytes
     *   |  
     *  delineates that this is the "short form" encoding.
     */

    // Need at least tag(1) + length(1)
    assert(N >= 2, "TLV too short");
    // Only support single-byte tag number (no high-tag-number 0x1F)
    // 0x1F = 31
    assert((tag & 0x1F) < 0x1F, "High-tag-number form not supported");
    // BER indefinite-length (0x80) is not supported here.
    // (Indefinite length has the entire first byte encoded as 0x80).
    // 0x80 = 128
    assert(elem_len != 0x80, "Indefinite length not supported");

    // Short form: content length is in low 7 bits
    // 0x80 = 128
    // 0x7F = 127
    if (elem_len & 0x80) == 0 {
        let content_len: u32 = (elem_len & 0x7F) as u32;
        let total: u32 = 2 + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
    // Long form: low 7 bits = number of following length bytes
    else {
        // 0x7F = 127
        let nlen: u32 = (elem_len & 0x7F) as u32;
        assert(nlen > 0, "Zero length-of-length");
        assert(nlen <= 4, "Length field too large"); // Consider renaming error to "Length > 4 not supported"
        assert(2 + nlen <= N, "Length bytes exceed buffer");
        // Parse big-endian content length
        let mut content_len: u32 = 0;
        for i in 0..nlen {
            content_len = content_len * 256 + (asn1[2 + i] as u32);
        }
        let total: u32 = 2 + nlen + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
}

// NOTE: this does NOT check that it is the FIRST occurrence of the needle; only that
// the needle exists somewhere in the haystack. If you want it to be the FIRST, you'll
// need to add some constraints (see example below).
// NOTE: the result of these constraints (as they stand) can be misleading and incorrect:
// If a malicious offset is returned by the unconstrained function, then this function could return 
// `HAYSTACK_SIZE`, which will be inferred to mean "the needle is not in this haystack"...
// but the needle MIGHT ACTUALLY BE in the haystack; it's just that a bad hint
// was returned by the unconstrained function.
// E.g. Finding [3, 4, 5] in [0, 1, 2, 3, 4, 5, 6, 7, 8].
// The correct answer is 3.
// But if a malicious prover returns `5` from the unconstrained function, 
// this function will return `9`, which the calling function will infer to mean 
// "needle not in this haystack".
//
// Some more comments below.
//
// Suggestion: add regression tests to catch these observations in future.
// In fact, we need a way to mock the return values of unconstrained calls in our tests. This has come
// up a few times on various Aztec projects too.
//
// Suggestion: consider throwing if the needle is not found. I haven't seen a case (yet) in this
// codebase where the circuit should gracefully continue if a call to this function fails to find the needle.
//
/// Find the index of the first occurrence of the needle in the haystack
/// Returns the index of the first occurrence of the needle in the haystack
/// Returns HAYSTACK_SIZE if the needle is not found
pub fn find_subarray_index<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    // Suggestion: static_assert(NEEDLE_SIZE <= HAYSTACK_SIZE, "needle cannot be bigger than the haystack");

    // Safety: This is safe because the offset is only used as a starting point
    // to verify the substring exists
    // Style: prefer snake_case for offset_unchecked.
    let offsetUnchecked = unsafe { find_subarray_index_unsafe(needle, haystack) };
    let mut offset = offsetUnchecked;
    // Check if offset is valid before attempting verification
    // Might be slightly more efficient to check:  
    // ```
    // std::static_assert(NEEDLE_SIZE != 0); // I can't think of a reason to call this function with an empty array...
    // // And then, now we know the NEEDLE_SIZE is >= 1, and we know u32 operations can't wrap:
    // if (offset_unchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
    //     for i in 0..NEEDLE_SIZE {
    //         // And then, to avoid the bug, I'd just do assertions, so that we fail if they're not met:
    //         assert_eq(haystack[offset_unchecked + i], needle[i]); // cheaper to assert equal than to assert not equal.
    //     }
    // } else {
    //    assert(offset_unchecked == HAYSTACK_SIZE);
    // }
    // ```
    //
    // ^^^ Notice, that this suggestion still doesn't fix the observation that
    // this function is not asserting that this is the FIRST occurrence. To do that, you'd
    // need to iterate through all earlier elements (which in circuit-land actually means
    // iterating through all elements) to assert that they DON'T contain the needle.
    // It would be something like:
    // ```
    // let mut before_offset = true; // will flip when we reach the claimed offset.
    // for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
    //     if i == offset_unchecked {
    //         before_offset = false;
    //         for _ in 0..NEEDLE_SIZE {
    //             assert_eq(haystack[offset_unchecked + i], needle[i]);
    //         }
    //     }
    //     let mut mismatch = false; // we want to find at least one mismatch at earlier offsets.
    //     for j in 0..NEEDLE_SIZE {
    //         mismatch |= (haystack[i + j] != needle[i]);
    //     }
    //     if before_offset {
    //         assert(mismatch);
    //     }
    // }
    //
    // if before_offset == true {
    //     assert(offset_unchecked == HAYSTACK_SIZE);
    // }
    // let offset = offset_unchecked
    // offset
    // ```

    if (offsetUnchecked < HAYSTACK_SIZE) & (offsetUnchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offsetUnchecked] != needle[i] {
                offset = HAYSTACK_SIZE;
            }
        }
    } else {
        // If offset is out of bounds, needle was not found
        offset = HAYSTACK_SIZE;
    }
    offset
}

// Visually inspected.
// Missing tests.
pub fn is_subarray_in_array<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> bool {
    find_subarray_index(needle, haystack) < HAYSTACK_SIZE // slightly more efficient to do `!=` here.
}

// Visually inspected.
/// Safety: This is safe because the offset is only used as a starting point
/// to verify the substring exists
pub unconstrained fn find_subarray_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    let mut result = HAYSTACK_SIZE; // Default to "not found" value
    // Handle edge cases
    if NEEDLE_SIZE == 0 {
        result = 0; // this seems like an incorrect return value: the empty array is not at index 0 in the haystack.
    } else if NEEDLE_SIZE <= HAYSTACK_SIZE {
        // Search for the needle in the haystack
        for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
            let mut found = true;
            for j in 0..NEEDLE_SIZE {
                if haystack[i + j] != needle[j] {
                    found = false;
                    break;
                }
            }
            if found {
                result = i;
                break;
            }
        }
    }
    result
}
