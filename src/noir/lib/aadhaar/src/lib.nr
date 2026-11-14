use common::{
    calculate_certificate_root_v1, CertificateTreeLeaf,
    compute_certificate_tree_root_using_hash_path_v1, hash_salt_dg1_dg2_hash_private_nullifier,
    normalize_dg2_hash, UIDAI_CERT_TYPE,
};
use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{
    constants::{DG1_LENGTH, SHA256_IDENTIFIER},
    get_expiry_date_from_mrz,
    types::{DG1Data, SaltedValue},
};

pub mod tests;

// Secure QR data: fields separated by 255. V2: "V2", email/mobile indicator, reference ID
// (last 4 Aadhaar digits + YYYYMMDDHHMMSSsss), name, DOB (DD-MM-YYYY), gender, 11 address
// fields, last 4 mobile digits, then the photo. V1 has no version or mobile digits, and ends
// with 32-byte email/mobile hashes as its indicator says (1 email, 2 mobile, 3 both).

pub global AADHAAR_MAX_DATA_LENGTH: u32 = 2048;
pub global AADHAAR_MAX_PHOTO_LENGTH: u32 = 1536;
pub global AADHAAR_DELIMITER_COUNT: u32 = 18;
// "AADHAAR"
pub global AADHAAR_NULLIFIER_DOMAIN: Field = 0x41414448414152;

global DELIMITER: u8 = 255;
global HEADER_SCAN_LENGTH: u32 = 1024;
global NAME_MAX_LENGTH: u32 = 64;
global MRZ_NAME_LENGTH: u32 = 39;
global LT: u8 = 60;

// Field positions in V1; V2 adds one for its version
global REFERENCE_ID_POSITION: u32 = 1;
global NAME_POSITION: u32 = 2;
global DOB_POSITION: u32 = 3;
global GENDER_POSITION: u32 = 4;

global DG1_HEADER: [u8; 5] = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
global DOCUMENT_TYPE: [u8; 2] = [73, 68];
global ISSUING_COUNTRY: [u8; 3] = [73, 78, 68];
// Aadhaar is issued to residents, not only citizens, so it proves no nationality
pub global AADHAAR_NATIONALITY: [u8; 3] = [88, 88, 88];
global DOCUMENT_NUMBER_MASK: [u8; 5] = [88, 88, 88, 88, 88];
// Aadhaar has no expiry, so the MRZ gets the signing date plus this many years
pub global AADHAAR_VALIDITY_YEARS: u32 = 10;
pub global CERTIFICATE_TREE_HEIGHT: u32 = 16;

pub struct AadhaarData {
    pub dg1: DG1Data,
    pub photo_hash: [u8; 32],
    pub signed_on: u64,
}

fn is_digit(c: u8) -> bool {
    (c >= 48) & (c <= 57)
}

fn digit(c: u8) -> u32 {
    assert(is_digit(c), "Expected a digit");
    (c - 48) as u32
}

fn mrz_char_value(c: u8) -> u32 {
    if is_digit(c) {
        (c - 48) as u32
    } else if (c >= 65) & (c <= 90) {
        (c - 55) as u32
    } else {
        0
    }
}

pub fn mrz_check_digit<let N: u32>(chars: [u8; N]) -> u8 {
    let weights: [u32; 3] = [7, 3, 1];
    let mut sum: u32 = 0;
    for i in 0..N {
        sum += mrz_char_value(chars[i]) * weights[i % 3];
    }
    ((sum % 10) as u8) + 48
}

pub fn is_v2(data: [u8; AADHAAR_MAX_DATA_LENGTH]) -> bool {
    let v2 = (data[0] == 86) & (data[1] == 50) & (data[2] == DELIMITER);
    assert(v2 | (is_digit(data[0]) & (data[1] == DELIMITER)), "Unsupported Aadhaar QR version");
    v2
}

// The prover's delimiter indices must be the first ones in the data, in order
pub fn verify_delimiter_indices(
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
    v2: bool,
) -> u32 {
    let count = if v2 {
        AADHAAR_DELIMITER_COUNT
    } else {
        AADHAAR_DELIMITER_COUNT - 2
    };
    let mut found: u32 = 0;
    for i in 0..HEADER_SCAN_LENGTH {
        if (found < count) & (data[i] == DELIMITER) {
            let expected = delimiter_indices[if found < count { found } else { 0 }];
            assert(expected == i, "Delimiter index mismatch");
            found += 1;
        }
    }
    assert(found == count, "Not every delimiter before the photo was found");
    count
}

fn field_start(delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT], position: u32) -> u32 {
    if position == 0 {
        0
    } else {
        delimiter_indices[position - 1] + 1
    }
}

fn field_bounds(delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT], position: u32) -> (u32, u32) {
    let start = field_start(delimiter_indices, position);
    let end = delimiter_indices[position];
    (start, end - start)
}

// Aadhaar does not tell the surname apart, so the whole name is the primary identifier
pub fn convert_name_to_mrz(
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    start: u32,
    length: u32,
) -> [u8; MRZ_NAME_LENGTH] {
    let mut converted: [u8; NAME_MAX_LENGTH] = [LT; NAME_MAX_LENGTH];
    let mut j: u32 = 0;
    let mut after_separator = true;
    for i in 0..NAME_MAX_LENGTH {
        if i < length {
            let c = data[start + i];
            let is_lower = (c >= 97) & (c <= 122);
            let is_upper = (c >= 65) & (c <= 90);
            let is_separator = (c == 32) | (c == 45) | (c == 44);
            if is_lower | is_upper {
                converted[j] = if is_lower { c - 32 } else { c };
                j += 1;
                after_separator = false;
            } else if is_separator & !after_separator {
                converted[j] = LT;
                j += 1;
                after_separator = true;
            }
        }
    }
    let mut name: [u8; MRZ_NAME_LENGTH] = [LT; MRZ_NAME_LENGTH];
    for i in 0..MRZ_NAME_LENGTH {
        name[i] = converted[i];
    }
    name
}

fn convert_dob_to_mrz(data: [u8; AADHAAR_MAX_DATA_LENGTH], start: u32, length: u32) -> [u8; 6] {
    assert(length == 10, "Date of birth must be DD-MM-YYYY");
    assert((data[start + 2] == 45) & (data[start + 5] == 45), "Date of birth must be DD-MM-YYYY");
    let mut dob: [u8; 6] = [0; 6];
    dob[0] = data[start + 8];
    dob[1] = data[start + 9];
    dob[2] = data[start + 3];
    dob[3] = data[start + 4];
    dob[4] = data[start];
    dob[5] = data[start + 1];
    for i in 0..6 {
        let _ = digit(dob[i]);
    }
    dob
}

fn convert_gender_to_mrz(data: [u8; AADHAAR_MAX_DATA_LENGTH], start: u32, length: u32) -> u8 {
    assert(length == 1, "Gender must be one character");
    let c = data[start];
    if (c == 77) | (c == 70) {
        c
    } else {
        LT
    }
}

fn read_reference_id(
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    start: u32,
    length: u32,
) -> ([u8; 4], [u8; 6]) {
    assert(length >= 12, "Reference ID is too short");
    let mut last_digits: [u8; 4] = [0; 4];
    for i in 0..4 {
        last_digits[i] = data[start + i];
        let _ = digit(last_digits[i]);
    }
    let year = digit(data[start + 6]) * 10 + digit(data[start + 7]);
    let expiry_year = (year + AADHAAR_VALIDITY_YEARS) % 100;
    let mut expiry: [u8; 6] = [0; 6];
    expiry[0] = (expiry_year / 10) as u8 + 48;
    expiry[1] = (expiry_year % 10) as u8 + 48;
    for i in 0..4 {
        expiry[2 + i] = data[start + 8 + i];
        let _ = digit(expiry[2 + i]);
    }
    (last_digits, expiry)
}

pub fn build_dg1(
    name: [u8; MRZ_NAME_LENGTH],
    last_digits: [u8; 4],
    dob: [u8; 6],
    gender: u8,
    expiry: [u8; 6],
) -> DG1Data {
    let mut mrz: [u8; 88] = [LT; 88];
    mrz[0] = DOCUMENT_TYPE[0];
    mrz[1] = DOCUMENT_TYPE[1];
    for i in 0..3 {
        mrz[2 + i] = ISSUING_COUNTRY[i];
        mrz[54 + i] = AADHAAR_NATIONALITY[i];
    }
    for i in 0..MRZ_NAME_LENGTH {
        mrz[5 + i] = name[i];
    }
    for i in 0..5 {
        mrz[44 + i] = DOCUMENT_NUMBER_MASK[i];
    }
    for i in 0..4 {
        mrz[49 + i] = last_digits[i];
    }
    let mut document_number: [u8; 9] = [0; 9];
    for i in 0..9 {
        document_number[i] = mrz[44 + i];
    }
    mrz[53] = mrz_check_digit(document_number);
    for i in 0..6 {
        mrz[57 + i] = dob[i];
        mrz[65 + i] = expiry[i];
    }
    mrz[63] = mrz_check_digit(dob);
    mrz[64] = gender;
    mrz[71] = mrz_check_digit(expiry);
    let mut optional: [u8; 14] = [LT; 14];
    for i in 0..14 {
        optional[i] = mrz[72 + i];
    }
    mrz[86] = mrz_check_digit(optional);
    let mut composite: [u8; 39] = [0; 39];
    for i in 0..10 {
        composite[i] = mrz[44 + i];
    }
    for i in 0..7 {
        composite[10 + i] = mrz[57 + i];
    }
    for i in 0..22 {
        composite[17 + i] = mrz[65 + i];
    }
    mrz[87] = mrz_check_digit(composite);

    let mut dg1: DG1Data = [0; DG1_LENGTH];
    for i in 0..5 {
        dg1[i] = DG1_HEADER[i];
    }
    for i in 0..88 {
        dg1[5 + i] = mrz[i];
    }
    dg1
}

fn trailing_hash_length(data: [u8; AADHAAR_MAX_DATA_LENGTH], v2: bool) -> u32 {
    if v2 {
        0
    } else {
        let indicator = digit(data[0]);
        assert(indicator <= 3, "Invalid email/mobile indicator");
        if indicator == 3 {
            64
        } else if indicator == 0 {
            0
        } else {
            32
        }
    }
}

pub fn hash_photo(
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    data_length: u32,
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
    delimiter_count: u32,
    v2: bool,
) -> [u8; 32] {
    let photo_start = delimiter_indices[delimiter_count - 1] + 1;
    let photo_end = data_length - trailing_hash_length(data, v2);
    assert(photo_end > photo_start, "The QR data has no photo");
    let photo_length = photo_end - photo_start;
    assert(photo_length <= AADHAAR_MAX_PHOTO_LENGTH, "The photo is too large");
    let mut photo: [u8; AADHAAR_MAX_PHOTO_LENGTH] = [0; AADHAAR_MAX_PHOTO_LENGTH];
    for i in 0..AADHAAR_MAX_PHOTO_LENGTH {
        let index = if i < photo_length { photo_start + i } else { 0 };
        if i < photo_length {
            photo[i] = data[index];
        }
    }
    sha256::sha256_var(photo, photo_length)
}

// The caller must have checked the signature over `data` up to `data_length`
pub fn parse_aadhaar_data(
    data: [u8; AADHAAR_MAX_DATA_LENGTH],
    data_length: u32,
    delimiter_indices: [u32; AADHAAR_DELIMITER_COUNT],
) -> AadhaarData {
    let v2 = is_v2(data);
    let delimiter_count = verify_delimiter_indices(data, delimiter_indices, v2);
    let offset = if v2 { 1 } else { 0 };

    let (reference_start, reference_length) =
        field_bounds(delimiter_indices, REFERENCE_ID_POSITION + offset);
    let (last_digits, expiry) = read_reference_id(data, reference_start, reference_length);
    let mut signing_date: [u8; 8] = [0; 8];
    for i in 0..8 {
        signing_date[i] = data[reference_start + 4 + i];
    }
    let (name_start, name_length) = field_bounds(delimiter_indices, NAME_POSITION + offset);
    let name = convert_name_to_mrz(data, name_start, name_length);
    let (dob_start, dob_length) = field_bounds(delimiter_indices, DOB_POSITION + offset);
    let dob = convert_dob_to_mrz(data, dob_start, dob_length);
    let (gender_start, gender_length) = field_bounds(delimiter_indices, GENDER_POSITION + offset);
    let gender = convert_gender_to_mrz(data, gender_start, gender_length);

    AadhaarData {
        dg1: build_dg1(name, last_digits, dob, gender, expiry),
        photo_hash: hash_photo(data, data_length, delimiter_indices, delimiter_count, v2),
        signed_on: Date::from_bytes_long_year(signing_date).to_timestamp(),
    }
}

// The signature changes with every QR code, so the nullifier comes from the photo, which doesn't
pub fn calculate_aadhaar_private_nullifier(photo_hash: [u8; 32]) -> Field {
    Poseidon2::hash(
        [AADHAAR_NULLIFIER_DOMAIN, normalize_dg2_hash(photo_hash)],
        2,
    )
}

pub fn verify_uidai_key_in_registry(
    pubkey: [u8; 256],
    certificate_registry_root: Field,
    schema_version: u16,
    timestamp: u32,
    certificate_tree_index: Field,
    certificate_tree_hash_path: [Field; CERTIFICATE_TREE_HEIGHT],
    certificate_tags: [Field; 3],
    uidai_cert_expiry: u32,
    uidai_cert_fingerprint: Field,
    revocation_tree_root: Field,
    masterlist_tree_root: Field,
) {
    let leaf = CertificateTreeLeaf {
        tags: certificate_tags,
        cert_type: UIDAI_CERT_TYPE,
        country: "IND",
        public_key: pubkey,
        expiry: uidai_cert_expiry,
        fingerprint: uidai_cert_fingerprint,
    };
    let certificate_tree_root = compute_certificate_tree_root_using_hash_path_v1(
        leaf,
        certificate_tree_index,
        certificate_tree_hash_path,
    );
    let computed_root = calculate_certificate_root_v1(
        schema_version,
        timestamp,
        certificate_tree_root,
        revocation_tree_root,
        masterlist_tree_root,
    );
    assert(computed_root == certificate_registry_root, "Certificate registry root mismatch");
}

pub fn commit_to_disclosure_aadhaar(
    aadhaar: AadhaarData,
    dg1_salt: Field,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
) -> (Field, Field) {
    let private_nullifier = calculate_aadhaar_private_nullifier(aadhaar.photo_hash);
    let comm_out = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(dg1_salt, aadhaar.dg1),
        SaltedValue::from_value(expiry_date_salt, get_expiry_date_from_mrz(aadhaar.dg1)),
        SaltedValue::from_value(dg2_hash_salt, normalize_dg2_hash(aadhaar.photo_hash)),
        SaltedValue::from_value(dg2_hash_salt, SHA256_IDENTIFIER),
        SaltedValue::from_value(private_nullifier_salt, private_nullifier),
    );
    (comm_out, private_nullifier)
}
