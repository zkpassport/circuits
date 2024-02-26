use dep::utils::{MRZ_BIRTHDATE_INDEX, PassportData, get_array_slice};
use dep::date::Date;

fn proof_of_age(
    passport_data: PassportData,
    age_required: u8,
    is_limit_minimum: bool,
    current_date_bytes: [u8; 8]
) {
    let bytes_mrz = passport_data.mrz.as_bytes();

    let birthdate_bytes = get_array_slice(bytes_mrz, MRZ_BIRTHDATE_INDEX, MRZ_BIRTHDATE_INDEX + 6);
    let birthdate = Date::from_bytes_short_year(
        birthdate_bytes,
        [current_date_bytes[2], current_date_bytes[3]]
    );

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    if is_limit_minimum {
        assert(current_date.gte(birthdate.add_years(age_required as u32)));
    } else {
        assert(current_date.lte(birthdate.add_years(age_required as u32)));
    }
}

fn main(
    passport_data: PassportData,
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct
    min_age_required: pub u8,
) {
    // Verify the age of the passport holder
    proof_of_age(passport_data, min_age_required, true, current_date.as_bytes());
}
