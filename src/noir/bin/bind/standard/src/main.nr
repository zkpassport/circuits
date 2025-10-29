use bind::calculate_param_commitment;
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
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
    // The data is public (via the parameter commitment) so verifiers can check the data
    // provided to the proof is correct
    data: [u8; 509],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry_from_date(salted_expiry_date.value, current_date);

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
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(data);
    (param_commitment, nullifier_type, nullifier)
}
