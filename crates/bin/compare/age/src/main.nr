use dep::utils::IDData;
use dep::compare_age::compare_age;

fn main(
    id_data: IDData,
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct
    min_age_required: pub u8,
    // The maximum age required is public so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: pub u8
) {
    // Verify the age of the ID holder
    compare_age(
        id_data,
        min_age_required,
        max_age_required,
        current_date.as_bytes()
    );
}
