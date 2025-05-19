use bind::calculate_param_commitment_sha2;
use commitment::nullify;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // The data is public (via the parameter commitment) so verifiers can check the data
    // provided to the proof is correct
    data: [u8; 500],
    // @committed
    // The expected hash is public (via the parameter commitment) so verifiers can check the hash
    // provided to the proof is correct
    expected_hash: [u8; 32],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
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
    let param_commitment = calculate_param_commitment_sha2(data, expected_hash);
    (param_commitment, nullifier)
}
