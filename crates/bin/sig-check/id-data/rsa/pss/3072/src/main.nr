use utils::{IDData, DSCData};
use sig_check_rsa::verify_id_signature;
use subcircuits::subcircuit_b_verification;

#[recursive]
fn main(comm_in: pub Field, salt: Field, id_data: IDData, dsc_data: DSCData, comm_out: pub Field) {
    subcircuit_b_verification(
        comm_in,
        salt,
        id_data,
        dsc_data,
        comm_out,
        id_data.sod_signature,
    );
    verify_id_signature::<3072, 1>(id_data, dsc_data);
}
