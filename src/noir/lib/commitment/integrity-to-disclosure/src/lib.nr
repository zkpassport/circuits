use common::{
    get_country_from_dg1, hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
    hash_salt_dg1_private_nullifier,
};
use utils::types::{DG1Data, EContentData, SignedAttrsData};

/*
############################################################
# Circuit C
############################################################
# Verifies the integrity of the ePassport data
############################################################

# Inputs/Outputs
############################################################
current_date
comm_in                 `assert comm_in == H(salt, country, signed_attr, sod_sig)`
salt
id_data
private_nullifier       `assert private_nullifier == H(dg1, sod_sig)`
comm_out                `H(salt, dg1, private_nullifier)`

# Checks
############################################################
- Check that passport expiry date <= current date
- Checks that the dg1 hash is present in e_content
- Checks that the hash of e_content is present in signed_attr
*/
pub fn commit_to_disclosure(
    comm_in: Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
    private_nullifier: Field,
) -> Field {
    let country = get_country_from_dg1(dg1);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size,
                dg1,
                e_content,
                private_nullifier,
            ),
        "Commitment from 2nd subproof doesn't match in 3rd subproof",
    );
    let comm_out = hash_salt_dg1_private_nullifier(salt_out, dg1, private_nullifier);
    comm_out
}
