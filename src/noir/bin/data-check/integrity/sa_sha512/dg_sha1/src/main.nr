// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_integrity::{
    check_dg1_sha1, check_signed_attributes_sha512, get_dg2_hash_from_econtent,
};
use utils::{
    constants::{SHA1_DIGEST_LENGTH, SHA1_IDENTIFIER},
    types::{DG1Data, EContentData, SignedAttrsData},
};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    private_nullifier: Field,
) -> pub Field {
    // Get the length of e_content by parsing the ASN.1
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_sha1
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    // Check the integrity of the data
    check_dg1_sha1(dg1, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length was checked in the ID data circuit and the whole signed attributes
    // was committed over in that same circuit
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_sha512(signed_attributes, e_content, e_content_size);

    // Get the hash of DG2 from eContent
    let dg2_hash = get_dg2_hash_from_econtent(e_content, e_content_size);

    let comm_out = commit_to_disclosure::<SHA1_DIGEST_LENGTH>(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        dg2_hash,
        SHA1_IDENTIFIER,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        private_nullifier,
    );
    comm_out
}
