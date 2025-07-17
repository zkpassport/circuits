// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::{check_dg1_sha256, check_signed_attributes_sha384};
use utils::timestamp::timestamp_to_date_string;

fn main(
    timestamp: pub u32,
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
    private_nullifier: Field,
) -> pub Field {
    // Convert unix timestamp to a YYYYMMDD date string
    let current_date = timestamp_to_date_string(timestamp);
    // Check the ID is not expired first
    check_expiry(dg1, current_date.as_bytes());
    // Check the integrity of the data
    check_dg1_sha256(dg1, e_content, dg1_offset_in_e_content);
    check_signed_attributes_sha384(
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
    );
    let comm_out = commit_to_disclosure(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        private_nullifier,
    );
    comm_out
}
