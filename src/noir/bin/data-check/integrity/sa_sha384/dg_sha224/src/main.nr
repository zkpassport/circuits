// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_expiry::check_expiry;
use data_check_integrity::{check_dg1_sha224, check_signed_attributes_sha384};
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    current_date: pub u64,
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    private_nullifier: Field,
) -> pub Field {
    // Check the ID is not expired first
    check_expiry(dg1, current_date);
    // Get the length of e_content by parsing the ASN.1
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_sha224
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    // Check the integrity of the data
    check_dg1_sha224(dg1, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length was checked in the ID data circuit and the whole signed attributes
    // was committed over in that same circuit
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_sha384(signed_attributes, e_content, e_content_size);
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
