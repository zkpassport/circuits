use commitment::nullify;
use disclose::{calculate_param_commitment, get_disclosed_bytes};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
// Suggestion: Use DG1Data type
    dg1: [u8; 95],
    // @committed
    // The disclose mask is public (via the parameter commitment) so verifiers can check the mask
    // ^^^ I see. I was going to comment that these masks should be `bool` types, or the existing `u8` types should be constrained to be `0 or 1` only, to prevent malicious usage of the `mask[i] * mrz[i]` calculation in `get_disclosed_bytes`.
    disclose_mask: [u8; 90], // Consider replacing `90` with a global constant.
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // @committed
    // The disclose bytes are public (via the parameter commitment) so verifiers can check the bytes
    let disclosed_bytes = get_disclosed_bytes(dg1, disclose_mask);
    let scoped_nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    (param_commitment, scoped_nullifier)
}
