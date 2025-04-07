use commitment::nullify;
use inclusion_check_country::{calculate_param_commitment, check_issuing_country_inclusion};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    country_list: [str<3>; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field) {
    // Check that the issuing country of the passport is in the list of countries
    check_issuing_country_inclusion(dg1, country_list);
    let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    let param_commitment = calculate_param_commitment(country_list);
    (param_commitment, nullifier)
}
