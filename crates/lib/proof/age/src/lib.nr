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

pub fn proof_of_age(id_data: IDData, min_age: u8, max_age: u8, current_date_bytes: [u8; 8]) {
    let birthdate = get_birthdate(id_data, current_date_bytes);

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    assert((min_age != 0) | (max_age != 0));

    if (min_age != 0) & (max_age == 0) {
        // Check if age is above min age
        assert(current_date.gte(birthdate.add_years(min_age as u32)));
    } else if (max_age != 0) & (min_age == 0) {
        // Check if age is below max age
        assert(current_date.lte(birthdate.add_years(max_age as u32)));
    } else {
        assert(min_age <= max_age);
        // Range
        assert(current_date.gte(birthdate.add_years(min_age as u32)));
        assert(current_date.lte(birthdate.add_years(max_age as u32)));
    }
}
