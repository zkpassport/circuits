use common::{
    get_country_from_dg1, hash_salt_country_signed_attr_dg1_e_content_private_nullifier,
    hash_salt_dg1_dg2_hash_private_nullifier, normalize_dg2_hash,
};
use utils::{get_expiry_date_from_mrz, types::{DG1Data, EContentData, SaltedValue, SignedAttrsData}};

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
pub fn commit_to_disclosure<let DG2_HASH_SIZE: u32>(
    comm_in: Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    salted_dg2_hash: SaltedValue<[u8; DG2_HASH_SIZE]>,
    salted_dg2_hash_type: SaltedValue<u32>,
    signed_attributes: SignedAttrsData,
    signed_attributes_size: Field,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<Field>,
) -> Field {
    let country = get_country_from_dg1(salted_dg1.value);
    assert(
        comm_in
            == hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
                salt_in,
                country,
                signed_attributes,
                signed_attributes_size,
                salted_dg1.value,
                e_content,
                salted_private_nullifier.value,
            ),
        "Commitment from 2nd subproof doesn't match in 3rd subproof",
    );
    let dg2_hash_normalized = normalize_dg2_hash(salted_dg2_hash.value);

    let salted_expiry_date =
        SaltedValue::from_value(expiry_date_salt, get_expiry_date_from_mrz(salted_dg1.value));

    let comm_out = hash_salt_dg1_dg2_hash_private_nullifier(
        salted_dg1,
        salted_expiry_date,
        SaltedValue::from_value(salted_dg2_hash.salt, dg2_hash_normalized),
        salted_dg2_hash_type,
        salted_private_nullifier,
    );
    comm_out
}
