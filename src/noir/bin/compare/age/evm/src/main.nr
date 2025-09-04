use commitment::nullify;
use compare_age::{calculate_param_commitment_sha2, compare_age};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // The current date timestamp is public (via the parameter commitment) so verifiers can check the date
    // provided to the proof is correct
    // Danger: need to assert that this `current_date` is equal to the `current_date` public input 
    // of the "Data Integrity Check" circuit. I can't find where that check is happening in the codebase.
    // It's not happening in the "outer circuit". Perhaps it happens in the Verifier code?
    // I read somewhere that as a lovely optimisation, a user generates the first 3 proofs when they
    // first scan their passport, and then they only need to generate the disclosure proof & outer proof on demand.
    // This particular disclosure circuit might not be amenable to that optimisation, since the Data Integrity Check
    // circuit would have to be re-proven with the current date.
    // Maybe you've already thought of all this :)
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
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(current_date, min_age_required, max_age_required);
    (param_commitment, nullifier)
}
