use commitment::nullify;
use inclusion_check_country::{calculate_param_commitment, check_nationality_inclusion};
use utils::dg1::DG1;
use utils::PROOF_TYPE_NATIONALITY_INCLUSION;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // @committed
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    country_list: [str<3>; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // Check that the nationality of the passport holder is in the list of countries
    let dg1_data = DG1::new(dg1);
    check_nationality_inclusion(dg1_data, country_list);
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
        calculate_param_commitment(PROOF_TYPE_NATIONALITY_INCLUSION, country_list);
    (param_commitment, nullifier)
}
