use commitment::nullify;
use exclusion_check_country::{calculate_param_commitment, check_issuing_country_exclusion};
use utils::dg1::DG1;
use utils::PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    // The list must be sorted in ascending order
    // For efficiency, no sorting is done in the circuit
    // since the fact that the list is already sorted can checked
    // by any verifier passing the public inputs to verify the proof
    country_list: [u32; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    let dg1_data = DG1::new(dg1);
    // Check that the issuing country of the passport is not in the list of countries
    check_issuing_country_exclusion(dg1_data, country_list);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment =
        calculate_param_commitment(PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION, country_list);
    (param_commitment, nullifier)
}
