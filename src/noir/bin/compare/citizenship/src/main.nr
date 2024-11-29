use compare_citizenship::compare_citizenship;

fn main(
    dg1: [u8; 95],
    // The country is public so verifiers can check
    // the country provided to the proof is correct
    country: pub str<3>,
) {
    // Verify the country of the passport holder
    compare_citizenship(dg1, country.as_bytes());
}
