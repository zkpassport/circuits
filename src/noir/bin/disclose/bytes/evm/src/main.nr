use commitment::nullify;
use disclose::{calculate_param_commitment_sha2, get_disclosed_bytes};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // The disclose mask is public (via the `param_commitment`) so verifiers can check the mask
    disclose_mask: [u8; 90],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // @committed
    // The disclosed bytes are public (via the `param_commitment`) so verifiers can check the bytes
    let disclosed_bytes = get_disclosed_bytes(dg1, disclose_mask);
    let scoped_nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment = calculate_param_commitment_sha2(disclose_mask, disclosed_bytes);
    (param_commitment, scoped_nullifier)
}
