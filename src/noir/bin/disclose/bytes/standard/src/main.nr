use commitment::nullify;
use data_check_expiry::check_expiry;
use disclose::{calculate_param_commitment, get_disclosed_bytes};
use utils::types::{DG1Data, DiscloseMask};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // The disclose mask is public (via the parameter commitment) so verifiers can check the mask
    disclose_mask: DiscloseMask,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(dg1, current_date);

    // @committed
    // The disclose bytes are public (via the parameter commitment) so verifiers can check the bytes
    let disclosed_bytes = get_disclosed_bytes(dg1, disclose_mask);
    let (scoped_nullifier, nullifier_type) = nullify(
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
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    (param_commitment, nullifier_type, scoped_nullifier)
}
