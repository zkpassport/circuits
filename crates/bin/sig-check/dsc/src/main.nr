use dep::utils::{DSCData, CSCACertData};
use dep::sig_check_rsa::verify_dsc_signature_4096;

fn main(
    dsc_data: DSCData,
    // The CSCA certificates are public knowledge and 
    // we want to let verifiers use the CSCA certificate
    // that they got from a source they trust to verify the proof
    csca_cert_data: pub CSCACertData
) {
    verify_dsc_signature_4096(dsc_data, csca_cert_data);
}
