use commitment::nullify;
use disclose::{calculate_param_commitment, get_disclosed_bytes};
use utils::types::{DG1Data, DiscloseMask};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // The disclose mask is public (via the parameter commitment) so verifiers can check the mask
    disclose_mask: DiscloseMask,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // @committed
    // The disclose bytes are public (via the parameter commitment) so verifiers can check the bytes
    let disclosed_bytes = get_disclosed_bytes(dg1, disclose_mask);
    let (scoped_nullifier, nullifier_type) = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    (param_commitment, nullifier_type, scoped_nullifier)
}
