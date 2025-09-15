use commitment::nullify;
use compare_date_lib::{calculate_param_commitment_sha2, compare_date, get_birthdate};
use utils::{constants::PROOF_TYPE_BIRTHDATE, types::DG1Data};

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
    // The minimum date required is public (via the parameter commitment) so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date timestamp is 0, it is not checked
    min_date: u64,
    // @committed
    // The maximum date required is public (via the parameter commitment) so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date timestamp is 0, it is not checked
    max_date: u64,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let birthdate = get_birthdate(dg1, current_date);
    // Verify the birthdate of the ID holder
    // Uses 1900 as the epoch year because birthdates can be before 1970 (the usual unix epoch)
    compare_date(birthdate, min_date, max_date, 1900);
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
