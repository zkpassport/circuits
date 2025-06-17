use super::{
    DG1_LENGTH, MRZ_DATE_LENGTH, MRZ_DOCUMENT_NUMBER_LENGTH, MRZ_DOCUMENT_TYPE_LENGTH,
    MRZ_GENDER_LENGTH, MRZ_LENGTH, MRZ_NAME_LENGTH, MRZ_NATIONALITY_LENGTH, MRZ_YOB_LENGTH,
};

// DG1 types
pub type DG1Data = [u8; DG1_LENGTH];
pub type MRZData = [u8; MRZ_LENGTH];

// MRZ types
pub type MRZName = [u8; MRZ_NAME_LENGTH];
pub type MRZDate = [u8; MRZ_DATE_LENGTH];
pub type MRZYOB = [u8; MRZ_YOB_LENGTH];
pub type MRZDocumentNumber = [u8; MRZ_DOCUMENT_NUMBER_LENGTH];
pub type MRZDocumentType = [u8; MRZ_DOCUMENT_TYPE_LENGTH];
pub type MRZNationality = [u8; MRZ_NATIONALITY_LENGTH];
pub type MRZGender = [u8; MRZ_GENDER_LENGTH];
pub type MRZIssuingCountry = [u8; MRZ_NATIONALITY_LENGTH];
