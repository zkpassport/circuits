use inclusion_check_country::check_country_inclusion;

fn main(
    dg1: [u8; 95],
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    country_list: pub [str<3>; 200],
) {
    // Check that nationality of the passport holder is not in the list of countries
    check_country_inclusion(dg1, country_list);
}
