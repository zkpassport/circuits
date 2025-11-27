use commitment::nullify;
use data_check_expiry::check_expiry;
use disclose::{calculate_param_commitment, get_disclosed_bytes};
use utils::types::{DG1Data, DiscloseMask, MRZExpiryDate, SaltedValue};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // The disclose mask is public (via the parameter commitment) so verifiers can check the mask
    disclose_mask: DiscloseMask,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    // @committed
    // The disclose bytes are public (via the parameter commitment) so verifiers can check the bytes
    let disclosed_bytes = get_disclosed_bytes(salted_dg1.value, disclose_mask);
    let (scoped_nullifier, nullifier_type) = nullify(
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
    let param_commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    (param_commitment, nullifier_type, scoped_nullifier)
}
