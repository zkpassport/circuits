use bind::calculate_param_commitment;
use commitment::nullify;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // The data is public (via the parameter commitment) so verifiers can check the data
    // provided to the proof is correct
    // TODO: change to [Field; 512] in the next breaking change update
    data: [Field; 500],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field,Field) {
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(data);
    (param_commitment, nullifier_type, nullifier)
}
