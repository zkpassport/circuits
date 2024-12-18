use commitment::nullify;
use compare_age::compare_age;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum age required is public so verifiers can check
    // the age provided to the proof is correct
    min_age_required: pub u8,
    // The maximum age required is public so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: pub u8,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    // Verify the age of the ID holder
    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date.as_bytes(),
    );
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    nullifier
}
