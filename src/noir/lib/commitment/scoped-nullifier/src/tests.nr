use super::nullify;
use babyjubjub::BabyJubJubPoint;
use common::hash_salt_dg1_dg2_hash_private_nullifier;
use utils::{
    constants::{
        ID_CARD_SAMPLE_DG1, NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER,
        SALTED_NULLIFIER, SAMPLE_DG1, SHA256_IDENTIFIER,
    },
    get_expiry_date_from_mrz,
    types::{OPRFProof, SaltedValue},
};

// Sample OPRF proof values from https://github.com/TaceoLabs/oprf-nr/blob/main/oprf_example/src/main.nr
// The OPRF input (preimage) is 42, and the output is the nullifier_secret below
fn sample_oprf_proof() -> OPRFProof {
    OPRFProof {
        pk: BabyJubJubPoint::new(
            5710999305174746446129006558187982651929018212457711080538180123406991257834,
            14822830093014637273720066510303560520096190665043878041612158237057634974510,
        ),
        dlog_e: 21651611782908870028415356680205912578677611779857889287526859934595727462023,
        dlog_s: 813348544856521250944635798658236115440111721634739064595636884345549099749,
        response_blinded: BabyJubJubPoint::new(
            3155679112931956901250628220045483261937665592711481372076828199008185725288,
            2295756075485931574186491588789693245723103184777309603040062940469350270432,
        ),
        response: BabyJubJubPoint::new(
            8239981253288452954319423631647803967161484725248664916163883751103616749641,
            10909431257409573621736924846505941126161080693380329853422959666368005023270,
        ),
        beta: 63865932500786004558985758765891911620034145599124743624338496685411118977,
    }
}

// The OPRF output for the sample proof with input 42
global SAMPLE_OPRF_OUTPUT: Field =
    652462475809871187303694058326169186632613845657706445893000132676028204998;

fn zero_oprf_proof() -> OPRFProof {
    OPRFProof {
        pk: BabyJubJubPoint::new(0, 0),
        dlog_e: 0,
        dlog_s: 0,
        response_blinded: BabyJubJubPoint::new(0, 0),
        response: BabyJubJubPoint::new(0, 0),
        beta: 0,
    }
}

#[test]
fn test_nullify() {
    let private_nullifier = 1;
    let service_scope = 2;
    let service_subscope = 3;
    let salt = 5;
    let dg2_hash_normalized = 6;
    let dg2_hash_type = SHA256_IDENTIFIER;

    let comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(salt, SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
    );
    let mock_comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(salt, ID_CARD_SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(ID_CARD_SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
    );

    // Non-salted nullifier (nullifier_secret = 0 means non-salted mode, no OPRF needed)
    let (non_salted_scoped_nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        SaltedValue::from_value(salt, SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
        service_scope,
        service_subscope,
        0,
        zero_oprf_proof(),
    );
    assert_eq(
        non_salted_scoped_nullifier,
        0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
    );
    assert_eq(nullifier_type, NON_SALTED_NULLIFIER);
    assert_eq(oprf_pk_hash, 0);

    // Non-salted mock nullifier
    let (non_salted_mock_scoped_nullifier, nullifier_type, oprf_pk_hash) = nullify(
        mock_comm_in,
        SaltedValue::from_value(salt, ID_CARD_SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(ID_CARD_SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
        service_scope,
        service_subscope,
        0,
        zero_oprf_proof(),
    );
    assert_eq(
        non_salted_mock_scoped_nullifier,
        0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
    );
    assert_eq(nullifier_type, NON_SALTED_MOCK_NULLIFIER);
    assert_eq(oprf_pk_hash, 0);

    // Assert that the non-salted mock nullifier is the same as the non-salted nullifier
    // since the private nullifier, service scope and service subscope are the same
    assert_eq(non_salted_mock_scoped_nullifier, non_salted_scoped_nullifier);
}

#[test]
fn test_nullify_salted() {
    let private_nullifier = 1;
    let service_scope = 2;
    let service_subscope = 3;
    let salt = 5;
    // dg2_hash must be 42 to match the OPRF sample proof input
    let dg2_hash_normalized = 42;
    let dg2_hash_type = SHA256_IDENTIFIER;
    let nullifier_secret = SAMPLE_OPRF_OUTPUT;

    let comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(salt, SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
    );
    let mock_comm_in = hash_salt_dg1_dg2_hash_private_nullifier(
        SaltedValue::from_value(salt, ID_CARD_SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(ID_CARD_SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
    );

    // Salted nullifier with valid OPRF proof
    let (salted_scoped_nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        SaltedValue::from_value(salt, SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
        service_scope,
        service_subscope,
        nullifier_secret,
        sample_oprf_proof(),
    );
    assert(salted_scoped_nullifier != 0);
    assert_eq(nullifier_type, SALTED_NULLIFIER);
    assert(oprf_pk_hash != 0);

    // Salted mock nullifier (ZKR country)
    let (salted_mock_scoped_nullifier, nullifier_type, oprf_pk_hash) = nullify(
        mock_comm_in,
        SaltedValue::from_value(salt, ID_CARD_SAMPLE_DG1),
        SaltedValue::from_value(salt, get_expiry_date_from_mrz(ID_CARD_SAMPLE_DG1)),
        SaltedValue::from_value(salt, dg2_hash_normalized),
        SaltedValue::from_value(salt, dg2_hash_type),
        SaltedValue::from_value(salt, private_nullifier),
        service_scope,
        service_subscope,
        nullifier_secret,
        sample_oprf_proof(),
    );
    assert(salted_mock_scoped_nullifier != 0);
    assert_eq(nullifier_type, SALTED_MOCK_NULLIFIER);
    assert(oprf_pk_hash != 0);

    // Salted mock nullifier should equal salted nullifier since
    // private_nullifier, service_scope, service_subscope, and nullifier_secret are the same
    assert_eq(salted_mock_scoped_nullifier, salted_scoped_nullifier);
}
