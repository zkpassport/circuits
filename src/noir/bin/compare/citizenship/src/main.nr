use commitment::nullify;
use compare_citizenship::compare_citizenship;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // The country is public so verifiers can check
    // the country provided to the proof is correct
    country: pub str<3>,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    // Verify the country of the passport holder
    compare_citizenship(dg1, country.as_bytes());
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
