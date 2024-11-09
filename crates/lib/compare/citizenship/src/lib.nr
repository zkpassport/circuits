use utils::{
    is_id_card, PASSPORT_MRZ_COUNTRY_INDEX, ID_CARD_MRZ_COUNTRY_INDEX, get_array_slice,
    get_mrz_from_dg1,
};

pub fn compare_citizenship(dg1: [u8; 95], country: [u8; 3]) {
    let mrz = get_mrz_from_dg1(dg1);

    let mut country_bytes: [u8; 3] = [0; 3];

    if is_id_card(dg1) {
        country_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_COUNTRY_INDEX,
            ID_CARD_MRZ_COUNTRY_INDEX + 3,
        );
    } else {
        country_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_COUNTRY_INDEX,
            PASSPORT_MRZ_COUNTRY_INDEX + 3,
        );
    }

    assert(country_bytes[0] == country[0]);
    assert(country_bytes[1] == country[1]);
    assert(country_bytes[2] == country[2]);
}
