use dep::utils::IDData;
use dep::compare_citizenship::compare_citizenship;

fn main(
    id_data: IDData,
    // The country is public so verifiers can check 
    // the country provided to the proof is correct
    country: pub str<3>
) {
    // Verify the country of the passport holder
    compare_citizenship(id_data, country.as_bytes());
}
