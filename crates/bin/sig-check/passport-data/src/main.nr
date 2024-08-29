use dep::utils::{IDData, DSCData};
use dep::sig_check_rsa::verify_id_signature;

fn main(id_data: IDData, dsc_data: DSCData) {
    verify_id_signature(id_data, dsc_data);
}
