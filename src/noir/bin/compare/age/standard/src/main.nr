use commitment::nullify;
use compare_age::{calculate_param_commitment, compare_age};
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // The current date timestamp is public (via the parameter commitment) so verifiers can check the date
    // provided to the proof is correct
    current_date: u64,
    // @committed
    // The minimum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    min_age_required: u8,
    // @committed
    // The maximum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: u8,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // Verify the age of the ID holder
    compare_age(dg1, min_age_required, max_age_required, current_date);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment =
        calculate_param_commitment(current_date, min_age_required, max_age_required);
    (param_commitment, nullifier)
}
