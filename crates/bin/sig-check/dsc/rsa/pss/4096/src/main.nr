use dep::utils::{DSCData, RSA4096Info};
use dep::sig_check_rsa::verify_dsc_signature_4096;

fn main(
    dsc_data: DSCData,
    rsa_4096_info: RSA4096Info
) {
    verify_dsc_signature_4096::<1>(dsc_data, rsa_4096_info);
}
