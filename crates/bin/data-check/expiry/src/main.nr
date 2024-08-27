use dep::utils::IDData;
use dep::data_check_expiry::check_expiry;

fn main(id_data: IDData, current_date: pub str<8>) {
    // Check the ID is not expired first
    check_expiry(id_data, current_date.as_bytes());
}
