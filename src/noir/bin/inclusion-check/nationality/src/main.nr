use commitment::nullify;
use inclusion_check_country::check_nationality_inclusion;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    country_list: pub [str<3>; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
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
    nullifier
}
