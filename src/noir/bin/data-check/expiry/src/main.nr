use data_check_expiry::check_expiry;
use utils::dg1::DG1;
use utils::types::DG1Data;

fn main(dg1: DG1Data, current_date: pub str<8>) {
    let dg1_data = DG1::new(dg1);
    // Check the ID is not expired first
    check_expiry(dg1_data, current_date.as_bytes());
}
