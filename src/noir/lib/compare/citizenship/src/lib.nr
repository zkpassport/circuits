use utils::dg1::DG1;
use utils::types::MRZNationality;

pub fn compare_citizenship(dg1: DG1, country: MRZNationality) {
    let country_bytes = dg1.get_nationality();

    assert(country_bytes[0] == country[0]);
    assert(country_bytes[1] == country[1]);
    assert(country_bytes[2] == country[2]);
}
