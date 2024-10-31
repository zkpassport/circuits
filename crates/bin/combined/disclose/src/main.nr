use dep::utils::{IDData, DSCData, DiscloseFlags, DisclosedData};
use dep::data_check_integrity::check_integrity_of_data;
use dep::sig_check_rsa::verify_id_signature;
use dep::disclose::get_disclosed_data;

fn main(id_data: IDData, dsc_data: DSCData, disclose_flags: DiscloseFlags) -> pub DisclosedData {
    // Verify the data has been signed correctly by the DSC
    verify_id_signature(id_data, dsc_data);
    // Check the integrity of the ID data
    check_integrity_of_data(id_data);
    // We now disclose the data requested
    get_disclosed_data(id_data, disclose_flags)
}
