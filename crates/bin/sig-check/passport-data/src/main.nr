use dep::utils::{IDData, DSCData};
use dep::sig_check_rsa::verify_id_signature_2048;

fn main(id_data: IDData, dsc_data: DSCData) {
    verify_id_signature_2048::<0>(id_data, dsc_data);
}
