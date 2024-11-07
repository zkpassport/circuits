use dep::utils::DSCData;
use dep::sig_check_ecdsa::verify_dsc_signature;

fn main(
    dsc_data: DSCData,
    ecdsa_p256_info: ECDSAP256Info
) {
    verify_dsc_signature(dsc_data, ecdsa_p256_info);
}
