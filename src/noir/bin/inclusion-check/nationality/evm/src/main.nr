use commitment::nullify;
use inclusion_check_country::{calculate_param_commitment_sha2, check_nationality_inclusion};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // @committed
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    country_list: [str<3>; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // Check that the nationality of the passport holder is in the list of countries
    check_nationality_inclusion(dg1, country_list);
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
    let param_commitment = calculate_param_commitment_sha2(country_list);
    (param_commitment, nullifier)
}
