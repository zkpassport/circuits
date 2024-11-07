use dep::utils::{DSCData, RSA2048Info};
use dep::sig_check_rsa::verify_dsc_signature_2048;

fn main(
    dsc_data: DSCData,
    rsa_2048_info: RSA2048Info
) {
    verify_dsc_signature_2048::<0>(dsc_data, rsa_2048_info);
}
