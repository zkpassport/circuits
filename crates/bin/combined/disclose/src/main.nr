use utils::{IDData, DSCData};
use data_check_integrity::check_integrity_of_data;
use sig_check_rsa::verify_id_signature_2048;
use disclose::get_disclosed_bytes;

fn main(id_data: IDData, dsc_data: DSCData, disclose_mask: [u8; 90]) -> pub [u8; 90] {
    // Verify the data has been signed correctly by the DSC
    verify_id_signature_2048(id_data, dsc_data);
    // Check the integrity of the ID data
    check_integrity_of_data(id_data);
    // We now disclose the data requested
    get_disclosed_bytes(id_data, disclose_mask)
}
