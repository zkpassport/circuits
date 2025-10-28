use commitment::nullify;
use compare_date_lib::{calculate_param_commitment, compare_date, get_expiry_date};
use data_check_expiry::check_expiry;
use utils::{constants::PROOF_TYPE_EXPIRY_DATE, types::DG1Data};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // The minimum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date timestamp is 0, it is not checked
    min_date: u64,
    // @committed
    // The maximum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date timestamp is 0, it is not checked
    max_date: u64,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(dg1, current_date);

    let expiry_date = get_expiry_date(dg1, current_date);
    // Verify the expiry date of the ID holder
    // Uses the usual unix epoch year of 1970 as the epoch year as expiry dates are in the future
    // and for expired documents, the expiry date is still way after 1970
    compare_date(expiry_date, min_date, max_date, 1970);
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment =
        calculate_param_commitment(PROOF_TYPE_EXPIRY_DATE, min_date, max_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salt,
        dg1,
        dg2_hash_normalized,
        dg2_hash_type,
        private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    (param_commitment, nullifier_type, nullifier)
}
