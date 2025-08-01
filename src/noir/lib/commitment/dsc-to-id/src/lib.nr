use common::{
    calculate_private_nullifier, get_country_from_dg1,
    hash_salt_country_signed_attr_dg1_e_content_private_nullifier, hash_salt_country_tbs,
};

/*
############################################################
# Circuit B
############################################################
# Verifies the DSC signed the ePassport
############################################################

# Inputs/Outputs
############################################################
comm_in         `assert comm_in == H(salt, country, dsc_pubkey)`
salt
id_data
dsc_data
sod_sig
comm_out        `H(salt, country, signed_attr, sod_sig)`

# Checks
############################################################
- Check that sod_sig is the signature of dsc_pubkey over signed_attr
*/

pub fn commit_to_id<let TBS_MAX_SIZE: u32, let SIG_SIZE: u32, let SA_SIZE: u32, let ECONTENT_SIZE: u32>(
    comm_in: Field,
    salt_in: Field,
    salt_out: Field,
    dg1: [u8; 95],
    tbs_certificate: [u8; TBS_MAX_SIZE],
    sod_signature: [u8; SIG_SIZE],
    signed_attributes: [u8; SA_SIZE],
    signed_attributes_size: Field,
    e_content: [u8; ECONTENT_SIZE],
) -> Field {
    let country = get_country_from_dg1(dg1);
    assert(
        comm_in == hash_salt_country_tbs(salt_in, country, tbs_certificate),
        "Commitment from 1st subproof doesn't match in 2nd subproof",
    );

    let private_nullifier = calculate_private_nullifier(dg1, e_content, sod_signature);
    let comm_out = hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
        salt_out,
        country,
        signed_attributes,
        signed_attributes_size,
        dg1,
        e_content,
        private_nullifier,
    );
    comm_out
}
