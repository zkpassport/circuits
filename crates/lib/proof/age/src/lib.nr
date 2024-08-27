use dep::utils::{
    PASSPORT_MRZ_LENGTH, PASSPORT_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_BIRTHDATE_INDEX, IDData,
    get_array_slice, is_id_card
};
use dep::date::Date;

fn get_birthdate(id_data: IDData, current_date: [u8; 8]) -> Date {
    let mut birthdate_bytes = [0 as u8; 6];
    let mrz_bytes = id_data.mrz.as_bytes();

    // Get the slice of the MRZ representing the birthdate
    if is_id_card(id_data) {
        birthdate_bytes = get_array_slice(mrz_bytes, ID_CARD_MRZ_BIRTHDATE_INDEX, ID_CARD_MRZ_BIRTHDATE_INDEX + 6);
    } else {
        // Otherwise it's an ID card
        birthdate_bytes = get_array_slice(mrz_bytes, PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_BIRTHDATE_INDEX + 6);
    }

    // Create a Date object from the birthdate using the current date as
    // the pivot year to differentiate between 20th and 21st centuries
    // as the format is "YYMMDD"
    Date::from_bytes_short_year(birthdate_bytes, [current_date[2], current_date[3]])
}

pub fn proof_of_age(
    id_data: IDData,
    age_required: u8,
    is_limit_minimum: bool,
    current_date_bytes: [u8; 8]
) {
    let birthdate = get_birthdate(id_data, current_date_bytes);

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    if is_limit_minimum {
        assert(current_date.gte(birthdate.add_years(age_required as u32)));
    } else {
        assert(current_date.lte(birthdate.add_years(age_required as u32)));
    }
}