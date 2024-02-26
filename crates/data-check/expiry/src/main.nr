use dep::utils::{PassportData, get_array_slice, MRZ_EXPIRY_DATE_INDEX};
use dep::date::Date;

fn check_expiry(passport_data: PassportData, current_date_bytes: [u8; 8]) {
    let bytes_mrz = passport_data.mrz.as_bytes();

    let threshold_year = Date::new(2070, 1, 1);
    let threshold_year_bytes = threshold_year.to_bytes();

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    let expiry_date_bytes = get_array_slice(bytes_mrz, MRZ_EXPIRY_DATE_INDEX, MRZ_EXPIRY_DATE_INDEX + 6);
    let expiry_date = Date::from_bytes_short_year(
        expiry_date_bytes,
        [threshold_year_bytes[2], threshold_year_bytes[3]]
    );

    assert(current_date.lt(expiry_date));
}

fn main(
    passport_data: PassportData,
    current_date: pub str<8>,
) {
    // Check the passport is not expired first
    check_expiry(passport_data, current_date.as_bytes());
}