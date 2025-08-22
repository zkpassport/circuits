// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::{check_dg1_sha1, check_signed_attributes_sha256};

fn main(
    current_date: pub u32,
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    signed_attributes: [u8; 220],
    e_content: [u8; 700],
    e_content_size: u32,
    private_nullifier: Field,
) -> pub Field {
    // Check the ID is not expired first
    check_expiry(dg1, current_date);
    // Check the integrity of the data
    check_dg1_sha1(dg1, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) as u64 };
    check_signed_attributes_sha256(signed_attributes, e_content, e_content_size);
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
