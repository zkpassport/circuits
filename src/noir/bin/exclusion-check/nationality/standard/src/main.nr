use commitment::nullify;
use exclusion_check_country::{calculate_param_commitment, check_nationality_exclusion};
use utils::{constants::PROOF_TYPE_NATIONALITY_EXCLUSION, types::DG1Data};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    // The list must be sorted in ascending order
    // For efficiency, the list is not sorted in the circuit
    // but it is checked to be sorted.
    // So it is up to the prover to properly sort the list before passing it to the circuit
    // or the proof will fail to generate
    country_list: [u32; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // Check that nationality of the passport holder is not in the list of countries
    check_nationality_exclusion(dg1, country_list);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        dg2_hash_normalized,
        dg2_hash_type,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment =
        calculate_param_commitment(PROOF_TYPE_NATIONALITY_EXCLUSION, country_list);
    (param_commitment, nullifier)
}
