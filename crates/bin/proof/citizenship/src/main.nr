use dep::utils::IDData;
use dep::proof_citizenship::proof_of_citizenship;

fn main(
    id_data: IDData,
    // The country is public so verifiers can check 
    // the country provided to the proof is correct
    country: pub str<3>
) {
    // Verify the country of the passport holder
    proof_of_citizenship(id_data, country.as_bytes());
}
