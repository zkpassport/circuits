use common::hash_salt_dg1_dg2_hash_private_nullifier;
use oprf::blinded_query::blinded_query;
use utils::types::{DG1Data, MRZExpiryDate, SaltedValue};

fn main(
    comm_in: pub Field,
    salted_dg1: SaltedValue<DG1Data>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    salted_private_nullifier: SaltedValue<Field>,
    beta: Field,
) -> pub (Field, Field) {
    // OPRF servers will verify `comm_in` here is same as the one in the facematch proof
    // Verify the commitment matches the provided salted values
    assert(
        comm_in
            == hash_salt_dg1_dg2_hash_private_nullifier(
                salted_dg1,
                salted_expiry_date,
                salted_dg2_hash,
                salted_dg2_hash_type,
                salted_private_nullifier,
            ),
        "Commitment mismatch in oprf_auth",
    );

    // Compute the blinded query from DG2
    let blinded = blinded_query(beta, salted_dg2_hash.value);
    (blinded.x, blinded.y)
}
