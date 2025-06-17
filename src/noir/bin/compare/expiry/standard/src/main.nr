use commitment::nullify;
use compare_date_lib::{calculate_param_commitment, compare_date};
use utils::dg1::DG1;
use utils::PROOF_TYPE_EXPIRY_DATE;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // The current date is public so verifiers can check the date
    // provided to the proof is correct
    current_date: str<8>,
    // @committed
    // The minimum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date is a string of 1 (i.e. "11111111") it is not checked
    min_date: str<8>,
    // @committed
    // The maximum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date is a string of 1 (i.e. "11111111") it is not checked
    max_date: str<8>,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let dg1_data = DG1::new(dg1);
    let expiry_date = dg1_data.get_expiry_date(current_date.as_bytes());

    // Verify the expiry date of the ID holder
    compare_date(expiry_date, min_date.as_bytes(), max_date.as_bytes());
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment =
        calculate_param_commitment(PROOF_TYPE_EXPIRY_DATE, current_date, min_date, max_date);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    (param_commitment, nullifier)
}
