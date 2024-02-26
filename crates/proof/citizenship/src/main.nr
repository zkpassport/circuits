use dep::utils::{PassportData, MRZ_COUNTRY_INDEX, get_array_slice};

fn proof_of_citizenship(passport_data: PassportData, country: [u8; 3]) {
    let bytes_mrz = passport_data.mrz.as_bytes();

    let country_bytes: [u8; 3] = get_array_slice(bytes_mrz, MRZ_COUNTRY_INDEX, MRZ_COUNTRY_INDEX + 3);

    assert(country_bytes[0] == country[0]);
    assert(country_bytes[1] == country[1]);
    assert(country_bytes[2] == country[2]);
}

fn main(
    passport_data: PassportData,
    // The country is public so verifiers can check 
    // the country provided to the proof is correct
    country: pub str<3>
) {
    // Verify the country of the passport holder
    proof_of_citizenship(passport_data, country.as_bytes());
}
