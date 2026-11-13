use super::{commit, main};
use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use common::hash_salt_dg1_dg2_hash_private_nullifier;
use utils::{
    constants::{SAMPLE_DG1, SHA256_IDENTIFIER},
    get_expiry_date_from_mrz,
    types::SaltedValue,
};

// Sample OPRF proof values from https://github.com/TaceoLabs/oprf-nr/blob/main/oprf_example/src/main.nr
global SAMPLE_PRIVATE_NULLIFIER: Field = 42;
global SAMPLE_BETA: Field =
    63865932500786004558985758765891911620034145599124743624338496685411118977;
global SAMPLE_DLOG_E: Field =
    21651611782908870028415356680205912578677611779857889287526859934595727462023;
global SAMPLE_DLOG_S: Field =
    813348544856521250944635798658236115440111721634739064595636884345549099749;

fn sample_pk() -> BabyJubJubPointInSubgroup {
    BabyJubJubPointInSubgroup::new(
        5710999305174746446129006558187982651929018212457711080538180123406991257834,
        14822830093014637273720066510303560520096190665043878041612158237057634974510,
    )
}

// Unblinded response, i.e. the registration id I
fn sample_response() -> BabyJubJubPoint {
    BabyJubJubPoint::new(
        8239981253288452954319423631647803967161484725248664916163883751103616749641,
        10909431257409573621736924846505941126161080693380329853422959666368005023270,
    )
}

global SALT: Field = 5;
global DG2_HASH_NORMALIZED: Field = 6;
global AUTH_SECRET: Field = 1234567890;

struct Inputs {
    comm_in: Field,
    registration_id: BabyJubJubPoint,
    oprf_pk: BabyJubJubPointInSubgroup,
    auth_commitment: Field,
    private_nullifier: Field,
    beta: Field,
    dlog_e: Field,
    dlog_s: Field,
    auth_secret: Field,
}

fn comm_in_for(private_nullifier: Field) -> Field {
    hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(SALT, SAMPLE_DG1),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(SALT, DG2_HASH_NORMALIZED),
        SaltedValue::from_value(SALT, SHA256_IDENTIFIER),
        SaltedValue::from_value(SALT, private_nullifier),
    )
}

fn valid_inputs() -> Inputs {
    Inputs {
        comm_in: comm_in_for(SAMPLE_PRIVATE_NULLIFIER),
        registration_id: sample_response(),
        oprf_pk: sample_pk(),
        auth_commitment: commit(SAMPLE_PRIVATE_NULLIFIER, AUTH_SECRET),
        private_nullifier: SAMPLE_PRIVATE_NULLIFIER,
        beta: SAMPLE_BETA,
        dlog_e: SAMPLE_DLOG_E,
        dlog_s: SAMPLE_DLOG_S,
        auth_secret: AUTH_SECRET,
    }
}

fn run(i: Inputs) {
    main(
        i.comm_in,
        i.registration_id,
        i.oprf_pk,
        i.auth_commitment,
        SaltedValue::from_value(SALT, SAMPLE_DG1),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(SALT, DG2_HASH_NORMALIZED),
        SaltedValue::from_value(SALT, SHA256_IDENTIFIER),
        SaltedValue::from_value(SALT, i.private_nullifier),
        i.beta,
        i.dlog_e,
        i.dlog_s,
        i.auth_secret,
    );
}

#[test]
fn test_registration_valid() {
    run(valid_inputs());
}

#[test]
fn test_commit_matches_typescript() {
    // computeAuthCommitment(42n, 1234567890n) from @zkpassport/utils (src/oprf/registration.ts)
    assert_eq(
        commit(42, 1234567890),
        13002763519127274454334235405378602711278687927439602127399400890018476844734,
    );
}

#[test]
fn test_commit_domain_separated() {
    // Different secret or different private nullifier give a different commitment
    assert(commit(42, 1) != commit(42, 2));
    assert(commit(42, 1) != commit(43, 1));
    assert(commit(42, 1) != commit(1, 42));
}

#[test(should_fail_with = "Commitment mismatch in oprf_registration")]
fn test_registration_wrong_comm_in() {
    let mut i = valid_inputs();
    i.comm_in = comm_in_for(43);
    run(i);
}

#[test(should_fail_with = "Private nullifier must be provided in the clear, not as a hash")]
fn test_registration_hidden_private_nullifier() {
    // A valid opening of P where pn is only given as its salted hash (value = 0) must not let
    // the prover run the OPRF on input 0
    let hidden_pn = SaltedValue::from_hash(SaltedValue::from_value(SALT, SAMPLE_PRIVATE_NULLIFIER)
        .get_hash());
    let comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(SALT, SAMPLE_DG1),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(SALT, DG2_HASH_NORMALIZED),
        SaltedValue::from_value(SALT, SHA256_IDENTIFIER),
        hidden_pn,
    );
    assert_eq(comm_in, comm_in_for(SAMPLE_PRIVATE_NULLIFIER));
    main(
        comm_in,
        sample_response(),
        sample_pk(),
        commit(0, AUTH_SECRET),
        SaltedValue::from_value(SALT, SAMPLE_DG1),
        SaltedValue::from_value(SALT, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(SALT, DG2_HASH_NORMALIZED),
        SaltedValue::from_value(SALT, SHA256_IDENTIFIER),
        hidden_pn,
        SAMPLE_BETA,
        SAMPLE_DLOG_E,
        SAMPLE_DLOG_S,
        AUTH_SECRET,
    );
}

#[test(should_fail)]
fn test_registration_other_passport() {
    // Valid opening of P for a different pn, but the OPRF transcript is for pn = 42
    let mut i = valid_inputs();
    i.private_nullifier = 43;
    i.comm_in = comm_in_for(43);
    i.auth_commitment = commit(43, AUTH_SECRET);
    run(i);
}

#[test(should_fail_with = "Beta cannot be zero")]
fn test_registration_zero_beta() {
    let mut i = valid_inputs();
    i.beta = 0;
    run(i);
}

#[test(should_fail)]
fn test_registration_wrong_beta() {
    let mut i = valid_inputs();
    i.beta = SAMPLE_BETA + 1;
    run(i);
}

#[test(should_fail)]
fn test_registration_wrong_oprf_pk() {
    // A response evaluated under a different key (e.g. k_c instead of k_reg) must not verify
    let mut i = valid_inputs();
    i.oprf_pk = BabyJubJubPointInSubgroup::generator();
    run(i);
}

#[test(should_fail)]
fn test_registration_wrong_dlog_proof() {
    let mut i = valid_inputs();
    i.dlog_e = SAMPLE_DLOG_E + 1;
    run(i);
}

#[test(should_fail_with = "Challenge verification failed")]
fn test_registration_wrong_registration_id() {
    // Any other point as I gives a blinded response the nodes' DLOG proof doesn't cover
    let mut i = valid_inputs();
    i.registration_id = BabyJubJubPoint::generator();
    run(i);
}

#[test(should_fail_with = "OPRF response must be in prime order subgroup")]
fn test_registration_id_with_torsion() {
    // I + T for the order 2 point T = (0, -1) is (-I.x, -I.y). For an even beta it unblinds to the
    // same response as I, which would give a second registration id for the same passport
    let mut i = valid_inputs();
    let id = sample_response();
    i.registration_id = BabyJubJubPoint::new(-id.x(), -id.y());
    run(i);
}

#[test(should_fail_with = "Point is not on the BabyJubJub curve")]
fn test_registration_id_off_curve() {
    let mut i = valid_inputs();
    i.registration_id = BabyJubJubPoint::new_unchecked(1, 1);
    run(i);
}

#[test(should_fail_with = "Auth secret cannot be zero")]
fn test_registration_zero_secret() {
    let mut i = valid_inputs();
    i.auth_secret = 0;
    i.auth_commitment = commit(SAMPLE_PRIVATE_NULLIFIER, 0);
    run(i);
}

#[test(should_fail_with = "Auth commitment mismatch in oprf_registration")]
fn test_registration_wrong_secret() {
    let mut i = valid_inputs();
    i.auth_secret = AUTH_SECRET + 1;
    run(i);
}

#[test(should_fail_with = "Auth commitment mismatch in oprf_registration")]
fn test_registration_commitment_for_other_pn() {
    // The commitment must be bound to the pn opened from P
    let mut i = valid_inputs();
    i.auth_commitment = commit(43, AUTH_SECRET);
    run(i);
}
