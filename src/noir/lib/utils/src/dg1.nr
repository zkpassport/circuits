use super::array::get_array_slice;
use super::{
    ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_EXPIRY_DATE_INDEX, ID_CARD_MRZ_NATIONALITY_INDEX,
    MRZ_LENGTH, PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_COUNTRY_INDEX,
    PASSPORT_MRZ_EXPIRY_DATE_INDEX, PASSPORT_MRZ_NATIONALITY_INDEX,
};
use super::ID_CARD_MRZ_COUNTRY_INDEX;
use super::ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX;
use super::ID_CARD_MRZ_DOCUMENT_TYPE_INDEX;
use super::ID_CARD_MRZ_GENDER_INDEX;
use super::ID_CARD_MRZ_NAME_INDEX;
use super::PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX;
use super::PASSPORT_MRZ_DOCUMENT_TYPE_INDEX;
use super::PASSPORT_MRZ_GENDER_INDEX;
use super::PASSPORT_MRZ_NAME_INDEX;
use super::types::{DG1Data, MRZData, MRZIssuingCountry, MRZNationality};
use super::types::MRZDate;
use super::types::MRZDocumentNumber;
use super::types::MRZDocumentType;
use super::types::MRZGender;
use super::types::MRZName;
use date::Date;

// D<<
global GERMANY_PASSPORT_CODE: MRZNationality = [68, 60, 60];
// DEU
global GERMANY_ISO_CODE: MRZNationality = [68, 69, 85];

pub struct DG1 {
    pub dg1: DG1Data,
    pub mrz: MRZData,
}

impl DG1 {
    pub fn new(dg1: DG1Data) -> Self {
        Self { dg1, mrz: get_mrz_from_dg1(dg1) }
    }

    pub fn get_mrz(self) -> MRZData {
        self.mrz
    }

    pub fn get_dg1(self) -> DG1Data {
        self.dg1
    }

    pub fn is_id_card(self) -> bool {
        is_id_card(self.dg1)
    }

    pub fn get_nationality(self) -> MRZNationality {
        let mut country_bytes = if self.is_id_card() {
            self.get_nationality_id_card()
        } else {
            self.get_nationality_passport()
        };

        // Handle the special case of Germany
        if (country_bytes == GERMANY_PASSPORT_CODE) {
            country_bytes = GERMANY_ISO_CODE;
        }

        country_bytes
    }


    pub fn get_issuing_country(self) -> MRZIssuingCountry {
        let mut country_bytes = if self.is_id_card() {
            self.get_issuing_country_id_card()
        } else {
            self.get_issuing_country_passport()
        };

        // Handle the special case of Germany
        if (country_bytes == GERMANY_PASSPORT_CODE) {
            country_bytes = GERMANY_ISO_CODE;
        }

        country_bytes
    }

    pub fn get_name_passport(self) -> MRZName {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_NAME_INDEX,
            PASSPORT_MRZ_NAME_INDEX + 39,
        )
    }

    pub fn get_name_id_card(self) -> MRZName {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_NAME_INDEX,
            ID_CARD_MRZ_NAME_INDEX + 39,
        )
    }

    pub fn get_nationality_passport(self) -> MRZNationality {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_NATIONALITY_INDEX,
            PASSPORT_MRZ_NATIONALITY_INDEX + 3,
        )
    }

    pub fn get_nationality_id_card(self) -> MRZNationality {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_NATIONALITY_INDEX,
            ID_CARD_MRZ_NATIONALITY_INDEX + 3,
        )
    }

    pub fn get_document_number_passport(self) -> MRZDocumentNumber {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
            PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + 9,
        )
    }

    pub fn get_document_number_id_card(self) -> MRZDocumentNumber {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
            ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + 9,
        )
    }

    pub fn get_expiry_date_id_card(self) -> MRZDate {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6,
        )
    }

    // TODO: make versions for each
    pub fn get_expiry_date_passport(self) -> MRZDate {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6,
        )
    }

    pub fn get_document_type_passport(self) -> MRZDocumentType {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_DOCUMENT_TYPE_INDEX,
            PASSPORT_MRZ_DOCUMENT_TYPE_INDEX + 2,
        )
    }

    pub fn get_document_type_id_card(self) -> MRZDocumentType {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_DOCUMENT_TYPE_INDEX,
            ID_CARD_MRZ_DOCUMENT_TYPE_INDEX + 2,
        )
    }

    pub fn get_gender_passport(self) -> MRZGender {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_GENDER_INDEX,
            PASSPORT_MRZ_GENDER_INDEX + 1,
        )
    }

    pub fn get_gender_id_card(self) -> MRZGender {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_GENDER_INDEX,
            ID_CARD_MRZ_GENDER_INDEX + 1,
        )
    }

    pub fn get_issuing_country_passport(self) -> MRZIssuingCountry {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_COUNTRY_INDEX,
            PASSPORT_MRZ_COUNTRY_INDEX + 3,
        )
    }

    pub fn get_issuing_country_id_card(self) -> MRZIssuingCountry {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_COUNTRY_INDEX,
            ID_CARD_MRZ_COUNTRY_INDEX + 3,
        )
    }

    pub fn get_date_of_birth_passport(self) -> MRZDate {
        get_array_slice(
            self.mrz,
            PASSPORT_MRZ_BIRTHDATE_INDEX,
            PASSPORT_MRZ_BIRTHDATE_INDEX + 6,
        )
    }

    pub fn get_date_of_birth_id_card(self) -> MRZDate {
        get_array_slice(
            self.mrz,
            ID_CARD_MRZ_BIRTHDATE_INDEX,
            ID_CARD_MRZ_BIRTHDATE_INDEX + 6,
        )
    }

    pub fn get_expiry_date(self, current_date: [u8; 8]) -> Date {
        // We base the threshold year for the expiry date on the current date plus 20 years
        // As most documents will have a 10 year validity (and some maybe 15 years?)
        // So with 20 years we should be safe
        let threshold_year = Date::from_bytes_long_year(current_date).add_years(20);
        let threshold_year_bytes = threshold_year.to_bytes();

        // Get the slice of the MRZ representing the expiry date
        if is_id_card(self.dg1) {
            self.get_date::<ID_CARD_MRZ_EXPIRY_DATE_INDEX>(threshold_year_bytes)
        } else {
            self.get_date::<PASSPORT_MRZ_EXPIRY_DATE_INDEX>(threshold_year_bytes)
        }
    }

    pub fn get_birthdate(self, current_date: [u8; 8]) -> Date {
        if is_id_card(self.dg1) {
            self.get_date::<ID_CARD_MRZ_BIRTHDATE_INDEX>(current_date)
        } else {
            self.get_date::<PASSPORT_MRZ_BIRTHDATE_INDEX>(current_date)
        }
    }

    pub fn get_date<let INDEX: u32>(self, threshold_year_bytes: [u8; 8]) -> Date {
        let date_bytes = get_array_slice(self.mrz, INDEX, INDEX + 6);

        // Create a Date object from the date using the current date as
        // the pivot year to differentiate between 20th and 21st centuries
        // as the format is "YYMMDD"
        Date::from_bytes_short_year(
            date_bytes,
            [threshold_year_bytes[2], threshold_year_bytes[3]],
        )
    }
}

pub fn get_mrz_from_dg1(dg1: DG1Data) -> MRZData {
    let mut mrz: MRZData = [0 as u8; MRZ_LENGTH];
    for i in 0..MRZ_LENGTH {
        mrz[i] = dg1[i + 5];
    }
    mrz
}

pub fn is_id_card(dg1: DG1Data) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[93] != 0) & (dg1[94] != 0)
}
