use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::check_integrity_of_data;

fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt: Field,
    dg1: [u8; 95],
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
    private_nullifier: Field,
) -> pub Field {
    // Check the ID is not expired first
    check_expiry(dg1, current_date.as_bytes());
    // Check the integrity of the data
    check_integrity_of_data(
        dg1,
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
        dg1_offset_in_e_content,
    );
    let comm_out = commit_to_disclosure(
        comm_in,
        salt,
        dg1,
        signed_attributes,
        signed_attributes_size as Field,
        private_nullifier,
    );
    comm_out
}
