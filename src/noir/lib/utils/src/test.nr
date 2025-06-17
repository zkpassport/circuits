use super::{PASSPORT_MRZ_COUNTRY_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX, PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_NATIONALITY_INDEX};
use super::types::{DG1Data, MRZName, MRZDOB, MRZDocumentNumber, MRZNationality};

// Testing utilities

/// DG1 Builder
/// Usage:
/// ```nr
/// let dg1 = DG1Builder::new([0; 95])
/// .with_document_number([68, 60, 60, etc...])
/// .with_name([68, 60, 60])
/// .with_dob([68, 60, 60])
/// .build();
pub struct DG1Builder {
    dg1: DG1Data,
}

impl DG1Builder {
    pub fn new(dg1: DG1Data) -> Self {
        Self { dg1 }
    }

    pub fn build(mut self: Self) -> DG1Data {
        self.dg1
    }

    pub fn with_country_code(mut self: Self, country_code: MRZNationality) -> Self {
        for i in 0..3 {
            // + 5 as it goes through an mrz decoding
            self.dg1[PASSPORT_MRZ_NATIONALITY_INDEX + i + 5] = country_code[i];
            self.dg1[PASSPORT_MRZ_COUNTRY_INDEX + i + 5] = country_code[i];
        }
        self
    }

    pub fn with_document_number(mut self: Self, document_number: MRZDocumentNumber) -> Self {
        for i in 0..9 {
            self.dg1[PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + i + 5] = document_number[i];
        }
        self
    }

    pub fn with_name(mut self: Self, name: MRZName) -> Self {
        for i in 0..39 {
            self.dg1[PASSPORT_MRZ_NAME_INDEX + i + 5] = name[i];
        }
        self
    }

    pub fn with_dob(mut self: Self, dob: MRZDOB) -> Self {
        for i in 0..6 {
            self.dg1[PASSPORT_MRZ_BIRTHDATE_INDEX + i + 5] = dob[i];
        }
        self
    }
}