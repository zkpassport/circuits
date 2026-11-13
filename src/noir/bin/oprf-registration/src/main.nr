use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use common::hash_salt_dg1_dg2_hash_private_nullifier;
use oprf::oprf_output::verified_oprf;
use poseidon2::bn254::permutation;
use utils::types::{DG1Data, MRZExpiryDate, SaltedValue};

mod tests;

// Domain separator for the DLOG equality proof, b"DLOG Equality Proof" (same as scoped-nullifier)
global DS_DLOG: Field = 1523098184080632582082867317389990410064981862;
// Domain separator for the OPRF output, b"OPRF" (same as scoped-nullifier). The output itself is
// not used here, only the checks `verified_oprf` makes on the way
global DS_OPRF: Field = 1330664006;
// Domain separator for the auth commitment, b"zkpassport-oprf-v2-commit"
global DS_COMMIT: Field = 768440808012663903960036740188911341512384528114964212050292;

/// Commitment to the auth secret `s`, bound to the private nullifier `pn`:
/// `commit(pn, s) = Poseidon2_t3([DS_COMMIT, pn, s])[1]`
pub fn commit(private_nullifier: Field, secret: Field) -> Field {
    permutation::t3([DS_COMMIT, private_nullifier, secret])[1]
}

/// Registration proof
///
/// Proves that:
/// 1. The prover knows the opening of `comm_in` (P), in particular the private nullifier `pn`
/// 2. The step-1 OPRF query was a blinding of `pn` with a nonzero `beta`, and the nodes' DLOG
///    equality proof verifies against `oprf_pk` (which the oracle pins to the `k_reg` public key)
/// 3. Unblinding the nodes' response with `beta` yields `registration_id` (I)
/// 4. The prover knows a nonzero `auth_secret` with `auth_commitment == commit(pn, auth_secret)`
///
/// Used in step 2 (register, commitment x'), step 3 (query, cached) and step 4 (rotate, y').
fn main(
    comm_in: pub Field,
    registration_id: pub BabyJubJubPoint,
    // Not checked to be in the prime order subgroup here: the oracle pins it to the k_reg public
    // key, as oprf-nr expects for the OPRF public key
    oprf_pk: pub BabyJubJubPointInSubgroup,
    auth_commitment: pub Field,
    salted_dg1: SaltedValue<DG1Data>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    salted_private_nullifier: SaltedValue<Field>,
    beta: Field,
    dlog_e: Field,
    dlog_s: Field,
    auth_secret: Field,
) {
    // 1 - opening of P
    assert(
        comm_in
            == hash_salt_dg1_dg2_hash_private_nullifier(
                salted_dg1,
                salted_expiry_date,
                salted_dg2_hash,
                salted_dg2_hash_type,
                salted_private_nullifier,
            ),
        "Commitment mismatch in oprf_registration",
    );
    let private_nullifier: Field = salted_private_nullifier.value;
    assert(
        private_nullifier != 0,
        "Private nullifier must be provided in the clear, not as a hash",
    );

    // 2 and 3 - the query was beta * encode(pn) with beta != 0, I is on the curve and in the prime
    // order subgroup, the nodes' blinded response is I * beta, and their DLOG equality proof
    // verifies against oprf_pk
    let registration_id = BabyJubJubPoint::new(registration_id.x(), registration_id.y());
    let _ = verified_oprf(
        beta,
        oprf_pk,
        dlog_e,
        dlog_s,
        registration_id,
        private_nullifier,
        DS_DLOG,
        DS_OPRF,
    );

    // 4 - knowledge of the auth secret behind the commitment
    assert(auth_secret != 0, "Auth secret cannot be zero");
    assert(
        auth_commitment == commit(private_nullifier, auth_secret),
        "Auth commitment mismatch in oprf_registration",
    );
}
