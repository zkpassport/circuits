use commitment::nullify;
use compare_citizenship::compare_citizenship;

// Q: Is this superfluous, given that this can be achieved with `disclose`?
fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    // The country is public so verifiers can check
    // the country provided to the proof is correct
    // Danger: these public inputs are inconsistent with those of other disclosure circuits that I've looked at so far.
    // In particular, I suspect this is breaking the rigid ordering that is expected by the Outer circuit.
    // The outer circuit expects public inputs of disclosure proofs to be in the order:
    // - comm_in
    // - service_scope
    // - service_subscope
    // - param_commitment
    // - scoped_nullifier
    //
    // But this circuit has no `param_commitment`, and although the `country` could feasibly replace
    // that `param_commitment` field, it is in the wrong position, and it is a str<3> type, which I
    // presume is naively serialized into 3 distinct fields.
    // So how is this circuit's public inputs "shape" compatible with the Outer circuit?
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
