use commitment::nullify;
use compare_age::{calculate_param_commitment_sha2, compare_age};
use data_check_expiry::check_expiry;
use utils::types::{DG1Data, SaltedValue};
use utils::types::MRZExpiryDate;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
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
    check_expiry(salted_dg1.value, current_date);

    // Verify the age of the ID holder
    compare_age(
        salted_dg1.value,
        min_age_required,
        max_age_required,
        current_date,
    );
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment = calculate_param_commitment_sha2(min_age_required, max_age_required);
    (param_commitment, nullifier_type, nullifier)
}
