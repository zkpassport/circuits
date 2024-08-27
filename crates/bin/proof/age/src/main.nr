use dep::utils::IDData;
use dep::proof_age::proof_of_age;

fn main(
    id_data: IDData,
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct
    min_age_required: pub u8
) {
    // Verify the age of the ID holder
    proof_of_age(id_data, min_age_required, true, current_date.as_bytes());
}
