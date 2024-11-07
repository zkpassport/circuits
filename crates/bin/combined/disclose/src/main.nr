use dep::utils::{IDData, RSA2048Info, DiscloseFlags, DisclosedData};
use dep::data_check_integrity::check_integrity_of_data;
use dep::sig_check_rsa::verify_id_signature_2048;
use dep::disclose::get_disclosed_bytes;

fn main(id_data: IDData, rsa_2048_info: RSA2048Info, disclose_mask: [u8; 90]) -> pub [u8; 90] {
    // Verify the data has been signed correctly by the DSC
    verify_id_signature_2048(id_data, rsa_2048_info);
    // Check the integrity of the ID data
    check_integrity_of_data(id_data);
    // We now disclose the data requested
    get_disclosed_bytes(id_data, disclose_mask)
}
