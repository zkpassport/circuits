use crate::{
    calculate_attested_digest, calculate_tier2_private_nullifier, commit_to_disclosure_attested,
};
use utils::{constants::SHA256_IDENTIFIER, types::{DG1Data, SaltedValue}};

// A TD3 passport DG1: tag, length, MRZ "P<FRADOE<<JANE<<..." for X12345678, born 1990-02-01,
// expiring 2030-04-03, zero-padded to the DG1 length
fn sample_dg1() -> DG1Data {
    let mut dg1: DG1Data = [0; 95];
    let bytes: [u8; 93] = [
        97, 91, 95, 31, 88, 80, 60, 70, 82, 65, 68, 79, 69, 60, 60, 74, 65, 78, 69, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 88, 49, 50, 51, 52, 53, 54, 55, 56, 60, 70, 82, 65, 57, 48, 48, 50, 48, 49, 54,
        70, 51, 48, 48, 52, 48, 51, 53, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 48,
        52,
    ];
    for i in 0..93 {
        dg1[i] = bytes[i];
    }
    dg1
}

// sha256("portrait")
fn sample_portrait_hash() -> [u8; 32] {
    [
        81, 197, 168, 41, 106, 3, 44, 231, 179, 1, 78, 102, 0, 12, 32, 208, 215, 89, 210, 233, 16,
        135, 63, 40, 250, 97, 7, 171, 1, 43, 248, 135,
    ]
}

#[test]
fn test_attested_digest_matches_sha256_of_dg1_and_portrait_hash() {
    // sha256(dg1 || sha256("portrait")), computed outside the circuit
    let expected: [u8; 32] = [
        69, 31, 10, 65, 229, 106, 116, 253, 122, 216, 15, 84, 46, 167, 26, 217, 239, 248, 239, 198,
        164, 202, 132, 75, 99, 149, 196, 199, 73, 109, 114, 133,
    ];
    assert_eq(calculate_attested_digest(sample_dg1(), sample_portrait_hash()), expected);
}

#[test]
fn test_attested_digest_changes_with_the_portrait() {
    let mut other_portrait = sample_portrait_hash();
    other_portrait[0] += 1;
    assert(
        calculate_attested_digest(sample_dg1(), sample_portrait_hash())
            != calculate_attested_digest(sample_dg1(), other_portrait),
    );
}

#[test]
fn test_nullifier_ignores_the_name() {
    let dg1 = sample_dg1();
    let mut renamed = dg1;
    // "DOE" -> "DOF": OCR noise in a name must not change the nullifier
    renamed[13] = 70;
    assert_eq(calculate_tier2_private_nullifier(dg1), calculate_tier2_private_nullifier(renamed));
}

#[test]
fn test_nullifier_changes_with_the_document_number() {
    let dg1 = sample_dg1();
    let mut other = dg1;
    other[49] = 89; // X -> Y
    assert(calculate_tier2_private_nullifier(dg1) != calculate_tier2_private_nullifier(other));
}

#[test]
fn test_nullifier_changes_with_the_date_of_birth() {
    let dg1 = sample_dg1();
    let mut other = dg1;
    other[64] = 49; // 1990-02-01 -> 1990-12-01
    assert(calculate_tier2_private_nullifier(dg1) != calculate_tier2_private_nullifier(other));
}

#[test]
fn test_commitment_is_deterministic_and_salt_bound() {
    let dg1 = sample_dg1();
    let digest = calculate_attested_digest(dg1, sample_portrait_hash());
    let commit = |dg1_salt: Field| {
        commit_to_disclosure_attested(
            SaltedValue::from_value(dg1_salt, dg1),
            2,
            3,
            SaltedValue::from_value(3, SHA256_IDENTIFIER),
            4,
            digest,
        )
    };
    let (comm_a, nullifier_a) = commit(1);
    let (comm_b, nullifier_b) = commit(1);
    let (comm_c, _) = commit(5);
    assert_eq(comm_a, comm_b);
    assert_eq(nullifier_a, nullifier_b);
    assert(comm_a != comm_c);
    assert(nullifier_a != 0);
}
