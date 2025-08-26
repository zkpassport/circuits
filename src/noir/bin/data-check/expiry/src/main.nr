use data_check_expiry::check_expiry;

fn main(dg1: [u8; 95], current_date_timestamp: pub u64) {
    // Check the ID is not expired first
    check_expiry(dg1, current_date_timestamp);
}
