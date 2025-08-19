use commitment::nullify;
use compare_date_lib::{calculate_param_commitment_sha2, compare_date, get_birthdate};
use utils::PROOF_TYPE_BIRTHDATE;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // The current date timestamp is public (via the parameter commitment) so verifiers can check the date
    // provided to the proof is correct
    current_date: u32,
    // @committed
    // The minimum date required is public (via the parameter commitment) so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date timestamp is 0, it is not checked
    min_date: u32,
    // @committed
    // The maximum date required is public (via the parameter commitment) so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date timestamp is 0, it is not checked
    max_date: u32,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let birthdate = get_birthdate(dg1, current_date);
    // Verify the birthdate of the ID holder
    compare_date(birthdate, min_date, max_date);
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
        calculate_param_commitment_sha2(PROOF_TYPE_BIRTHDATE, current_date, min_date, max_date);
    (param_commitment, nullifier)
}
