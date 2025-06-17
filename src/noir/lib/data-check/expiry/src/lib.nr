use date::Date;
use utils::dg1::DG1;

pub fn check_expiry(dg1: DG1, current_date_bytes: [u8; 8]) {
    // We base the threshold year for the expiry date on the current date plus 30 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 30 years we should be safe
    let threshold_year = Date::from_bytes_long_year(current_date_bytes).add_years(30);
    let threshold_year_bytes = threshold_year.to_bytes();

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    let mut expiry_date_bytes = [0 as u8; 6];

    if dg1.is_id_card() {
        expiry_date_bytes = dg1.get_expiry_date_id_card();
    } else {
        expiry_date_bytes = dg1.get_expiry_date_passport();
    }

    let expiry_date = Date::from_bytes_short_year(
        expiry_date_bytes,
        [threshold_year_bytes[2], threshold_year_bytes[3]],
    );

    assert(current_date.lt(expiry_date));
}
