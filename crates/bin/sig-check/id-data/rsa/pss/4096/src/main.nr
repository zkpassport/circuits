use dep::utils::{IDData, RSA4096Info};
use dep::sig_check_rsa::verify_id_signature_4096;

fn main(
    id_data: IDData,
    rsa_4096_info: RSA4096Info
) {
    verify_id_signature_4096::<1>(id_data, rsa_4096_info);
}
