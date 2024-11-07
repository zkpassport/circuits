use dep::utils::{IDData, ECDSAP256Info};
use dep::sig_check_ecdsa::verify_id_signature;

fn main(
    id_data: IDData,
    ecdsa_p256_info: ECDSAP256Info
) {
    verify_id_signature(id_data, ecdsa_p256_info);
}
