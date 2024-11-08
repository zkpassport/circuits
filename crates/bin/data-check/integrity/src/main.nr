use utils::IDData;
use data_check_integrity::check_integrity_of_data;
use data_check_expiry::check_expiry;
use subcircuits::subcircuit_c_verification;

#[recursive]
fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt: Field,
    id_data: IDData,
    private_nullifier: Field,
    comm_out: pub Field,
) {
    subcircuit_c_verification(
        current_date,
        comm_in,
        salt,
        id_data,
        private_nullifier,
        comm_out,
    );
    // Check the ID is not expired first
    check_expiry(id_data, current_date.as_bytes());
    // Check the integrity of the data
    check_integrity_of_data(id_data);
}
