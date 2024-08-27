use dep::utils::IDData;
use dep::std::sha256;
use dep::data_check_integrity::check_integrity_of_data;

fn main(id_data: IDData) {
    check_integrity_of_data(id_data);
}
