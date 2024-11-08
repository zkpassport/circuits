use dep::utils::IDData;
use dep::std::sha256;
use dep::data_check_integrity::check_integrity_of_data;
use dep::data_check_expiry::check_expiry;

fn main(id_data: IDData, current_date: pub str<8>) {
    // Check the ID is not expired first
    check_expiry(id_data, current_date.as_bytes());
    check_integrity_of_data(id_data);
}
