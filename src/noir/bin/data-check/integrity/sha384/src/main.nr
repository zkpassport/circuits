// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::check_integrity_of_data_sha384;
use utils::types::DG1Data;
use utils::dg1::DG1;

fn main(
    current_date: pub str<8>,
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
    private_nullifier: Field,
) -> pub Field {
    let dg1_data = DG1::new(dg1);
    // Check the ID is not expired first
    check_expiry(dg1_data, current_date.as_bytes());
    // Check the integrity of the data
    check_integrity_of_data_sha384(
        dg1_data,
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
        dg1_offset_in_e_content,
    );
    let comm_out = commit_to_disclosure(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        signed_attributes,
        signed_attributes_size as Field,
        private_nullifier,
    );
    comm_out
}
