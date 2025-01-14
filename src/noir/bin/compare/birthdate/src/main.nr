use commitment::nullify;
use compare_date_lib::{compare_date, get_birthdate};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: pub str<8>,
    // The minimum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date is a string of 1 (i.e. "11111111") it is not checked
    min_date: pub str<8>,
    // The maximum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date is a string of 1 (i.e. "11111111") it is not checked
    max_date: pub str<8>,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    let birthdate = get_birthdate(dg1, current_date.as_bytes());
    // Verify the birthdate of the ID holder
    compare_date(birthdate, min_date.as_bytes(), max_date.as_bytes());
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
