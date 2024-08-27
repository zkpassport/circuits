use dep::utils::{IDData, DSCData};
use dep::proof_age::proof_of_age;
use dep::data_check_integrity::check_integrity_of_data;
use dep::sig_check_passport_data::verify_id_signature;

fn main(
    id_data: IDData,
    dsc_data: DSCData,
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct
    min_age_required: pub u8
) {
    // Verify the data has been signed correctly by the DSC
    verify_id_signature(id_data, dsc_data);
    // Check the integrity of the ID data
    check_integrity_of_data(id_data);
    // Now we sure the data is correct, we verify the age of the ID holder
    proof_of_age(id_data, min_age_required, true, current_date.as_bytes());
}
