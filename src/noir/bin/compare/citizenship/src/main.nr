use commitment::nullify;
use compare_citizenship::compare_citizenship;
use utils::dg1::DG1;
use utils::types::DG1Data;

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    // The country is public so verifiers can check
    // the country provided to the proof is correct
    country: pub str<3>,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub Field {
    // Verify the country of the passport holder
    let dg1_data = DG1::new(dg1);
    compare_citizenship(dg1_data, country.as_bytes());

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
