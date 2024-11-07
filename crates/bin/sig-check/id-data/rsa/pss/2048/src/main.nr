use dep::utils::{IDData, RSA2048Info};
use dep::sig_check_rsa::verify_id_signature_2048;

fn main(
    id_data: IDData,
    rsa_2048_info: RSA2048Info
) {
    verify_id_signature_2048::<1>(id_data, rsa_2048_info);
}
