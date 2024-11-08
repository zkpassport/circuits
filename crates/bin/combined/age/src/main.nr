use utils::{IDData, DSCData};
use compare_age::compare_age;
use data_check_integrity::check_integrity_of_data;
use sig_check_rsa::verify_id_signature;

fn main(
    id_data: IDData,
    dsc_data: DSCData,
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct'
    // If the minimum age is 0, it is not checked
    min_age_required: pub u8,
    // The maximum age required is public so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: pub u8,
) {
    // Verify the data has been signed correctly by the DSC
    verify_id_signature::<2048, 0>(id_data, dsc_data);
    // Check the integrity of the ID data
    check_integrity_of_data(id_data);
    // Now we make sure the data is correct, we verify the age of the ID holder
    compare_age(
        id_data,
        min_age_required,
        max_age_required,
        current_date.as_bytes(),
    );
}
