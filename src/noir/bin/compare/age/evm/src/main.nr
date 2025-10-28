use commitment::nullify;
use compare_age::{calculate_param_commitment_sha2, compare_age};
use data_check_expiry::check_expiry;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // The minimum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    min_age_required: u8,
    // @committed
    // The maximum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: u8,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(dg1, current_date);

    // Verify the age of the ID holder
    compare_age(dg1, min_age_required, max_age_required, current_date);
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
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(min_age_required, max_age_required);
    (param_commitment, nullifier_type, nullifier)
}
