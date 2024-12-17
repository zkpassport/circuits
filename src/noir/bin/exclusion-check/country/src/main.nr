use commitment::nullify;
use exclusion_check_country::check_country_exclusion;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    // The list must be sorted in ascending order
    // For efficieny, no sorting is done in the circuit
    // since the fact that the list is already sorted can checked
    // by any verifier passing the public inputs to verify the proof
    country_list: pub [u32; 200],
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    // Check that nationality of the passport holder is not in the list of countries
    check_country_exclusion(dg1, country_list);
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
