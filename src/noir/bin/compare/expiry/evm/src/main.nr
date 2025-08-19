use commitment::nullify;
use compare_date_lib::{calculate_param_commitment_sha2, compare_date, get_expiry_date};
use utils::PROOF_TYPE_EXPIRY_DATE;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // The current date timestamp is public so verifiers can check the date
    // provided to the proof is correct
    current_date: u32,
    // @committed
    // The minimum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date timestamp is 0, it is not checked
    min_date: u32,
    // @committed
    // The maximum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date timestamp is 0, it is not checked
    max_date: u32,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let expiry_date = get_expiry_date(dg1, current_date);
    // Verify the expiry date of the ID holder
    compare_date(expiry_date, min_date, max_date);
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(PROOF_TYPE_EXPIRY_DATE, current_date, min_date, max_date);
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
