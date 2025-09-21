use super::nullify;
use common::hash_salt_dg1_private_nullifier;
use utils::constants::{SAMPLE_DG1, ID_CARD_SAMPLE_DG1, NON_SALTED_NULLIFIER, SALTED_NULLIFIER, NON_SALTED_MOCK_NULLIFIER, SALTED_MOCK_NULLIFIER};

#[test]
fn test_nullify() {
    let private_nullifier = 1;
    let service_scope = 2;
    let service_subscope = 3;
    let nullifier_secret = 4;

    let salt = 5;

    let comm_in = hash_salt_dg1_private_nullifier(salt, SAMPLE_DG1, private_nullifier);
    let mock_comm_in = hash_salt_dg1_private_nullifier(salt, ID_CARD_SAMPLE_DG1, private_nullifier);

    // Non-salted nullifier
    let (non_salted_scoped_nullifier, nullifier_type) = nullify(comm_in, salt, SAMPLE_DG1, private_nullifier, service_scope, service_subscope, 0);
    assert_eq(non_salted_scoped_nullifier, 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8);
    assert_eq(nullifier_type, NON_SALTED_NULLIFIER);

    // Salted nullifier
    let (salted_scoped_nullifier, nullifier_type) = nullify(comm_in, salt, SAMPLE_DG1, private_nullifier, service_scope, service_subscope, nullifier_secret);
    assert_eq(salted_scoped_nullifier, 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9);
    assert_eq(nullifier_type, SALTED_NULLIFIER);

    // Assert that the non-salted nullifier is different from the salted nullifier
    // since the secret was used to salt the nullifier in one case and not in the other
    assert(non_salted_scoped_nullifier != salted_scoped_nullifier);

    // Non-salted mock nullifier
    let (non_salted_mock_scoped_nullifier, nullifier_type) = nullify(mock_comm_in, salt, ID_CARD_SAMPLE_DG1, private_nullifier, service_scope, service_subscope, 0);
    assert_eq(non_salted_mock_scoped_nullifier, 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8);
    assert_eq(nullifier_type, NON_SALTED_MOCK_NULLIFIER);

    // Salted mock nullifier
    let (salted_mock_scoped_nullifier, nullifier_type) = nullify(mock_comm_in, salt, ID_CARD_SAMPLE_DG1, private_nullifier, service_scope, service_subscope, nullifier_secret);
    assert_eq(salted_mock_scoped_nullifier, 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9);
    assert_eq(nullifier_type, SALTED_MOCK_NULLIFIER);

    // Assert that the non-salted mock nullifier is different from the salted mock nullifier
    // since the secret was used to salt the nullifier in one case and not in the other
    assert(non_salted_mock_scoped_nullifier != salted_mock_scoped_nullifier);

    // Assert that the non-salted mock nullifier is the same as the non-salted nullifier
    // since the private nullifier, service scope and service subscope are the same
    assert_eq(non_salted_mock_scoped_nullifier, non_salted_scoped_nullifier);

    // Assert that the salted mock nullifier is the same as the salted nullifier
    // since the private nullifier, service scope and service subscope are the same
    assert_eq(salted_mock_scoped_nullifier, salted_scoped_nullifier);


}