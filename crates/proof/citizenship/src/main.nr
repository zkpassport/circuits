use dep::utils::{IDData, is_id_card, PASSPORT_MRZ_COUNTRY_INDEX, ID_CARD_MRZ_COUNTRY_INDEX, get_array_slice};

fn proof_of_citizenship(id_data: IDData, country: [u8; 3]) {
    let bytes_mrz = id_data.mrz.as_bytes();

    let mut country_bytes: [u8; 3] = [0; 3];

    if is_id_card(id_data) {
        country_bytes = get_array_slice(bytes_mrz, ID_CARD_MRZ_COUNTRY_INDEX, ID_CARD_MRZ_COUNTRY_INDEX + 3);
    } else {
        country_bytes = get_array_slice(bytes_mrz, PASSPORT_MRZ_COUNTRY_INDEX, PASSPORT_MRZ_COUNTRY_INDEX + 3);
    }

    assert(country_bytes[0] == country[0]);
    assert(country_bytes[1] == country[1]);
    assert(country_bytes[2] == country[2]);
}

fn main(
    id_data: IDData,
    // The country is public so verifiers can check 
    // the country provided to the proof is correct
    country: pub str<3>
) {
    // Verify the country of the passport holder
    proof_of_citizenship(id_data, country.as_bytes());
}
