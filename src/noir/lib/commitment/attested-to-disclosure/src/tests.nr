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

// The ICAO 9303 sample TD1 ID card: "I<UTOD231458907...", born 1974-08-12, expiring 2012-04-15
fn sample_id_card_dg1() -> DG1Data {
    [
        97, 91, 95, 31, 90, 73, 60, 85, 84, 79, 68, 50, 51, 49, 52, 53, 56, 57, 48, 55, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 55, 52, 48, 56, 49, 50, 50, 70, 49, 50, 48,
        52, 49, 53, 57, 85, 84, 79, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 54, 69, 82, 73, 75,
        83, 83, 79, 78, 60, 60, 65, 78, 78, 65, 60, 77, 65, 82, 73, 65, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60,
    ]
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
fn test_nullifier_changes_with_the_expiry_date() {
    let dg1 = sample_dg1();
    let mut other = dg1;
    other[71] = 49; // 2030-04-03 -> 2031-04-03
    assert(calculate_tier2_private_nullifier(dg1) != calculate_tier2_private_nullifier(other));
}

// The sample ID card with its number continued in the optional data: "D23145890" + "7342<",
// the check digit position left empty, as ICAO 9303-5 writes a number longer than 9 characters
fn overflowing_id_card_dg1() -> DG1Data {
    let mut dg1 = sample_id_card_dg1();
    let overflow: [u8; 6] = [60, 55, 51, 52, 50, 60]; // "<7342<"
    for i in 0..6 {
        dg1[5 + 14 + i] = overflow[i];
    }
    dg1
}

#[test]
fn test_nullifier_takes_a_long_document_number_whole() {
    let dg1 = overflowing_id_card_dg1();
    let mut other = dg1;
    other[5 + 17] = 57; // the 12th character of the number: 4 -> 9
    assert(calculate_tier2_private_nullifier(dg1) != calculate_tier2_private_nullifier(other));
}

#[test]
fn test_nullifier_ignores_optional_data_after_a_short_document_number() {
    let dg1 = sample_id_card_dg1();
    let mut other = dg1;
    other[5 + 20] = 65; // optional data, the number having its check digit in place
    assert_eq(calculate_tier2_private_nullifier(dg1), calculate_tier2_private_nullifier(other));
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

// Prints the values the TypeScript twins in @zkpassport/utils are checked against:
// `nargo test --package attested_to_disclosure_commitment --show-output test_vectors`
#[test]
fn test_vectors_for_typescript() {
    let dg1 = sample_dg1();
    let digest = calculate_attested_digest(dg1, sample_portrait_hash());
    let (comm_out, private_nullifier) = commit_to_disclosure_attested(
        SaltedValue::from_value(1, dg1),
        2,
        3,
        SaltedValue::from_value(3, SHA256_IDENTIFIER),
        4,
        digest,
    );
    // These pin the Tier 2 nullifier: a change here gives every camera-read ID a new identity,
    // so it must be deliberate. The TypeScript twins (circuits.test.ts, @zkpassport/utils) use
    // the same values.
    assert_eq(
        private_nullifier,
        0x064c866cb0248d050c72dc3a01c74d839bbc18df5600debb0b2e2ff1a645c447,
    );
    let id_card_nullifier = calculate_tier2_private_nullifier(sample_id_card_dg1());
    assert_eq(
        id_card_nullifier,
        0x02c7905c961b56ce7050e0cc7873e9d2bbabfca8835d7eb74619eaa3f2a8a5ae,
    );
    // Germany writes D<< as its issuing country, which reads as DEU
    let mut german = sample_dg1();
    german[7] = 68;
    german[8] = 60;
    german[9] = 60;
    let german_nullifier = calculate_tier2_private_nullifier(german);
    assert_eq(german_nullifier, 0x2e2744a716091a7543c8953ae0f37f99203ceb3007b5947ad303400802d57ea4);
    let overflow_nullifier = calculate_tier2_private_nullifier(overflowing_id_card_dg1());
    assert_eq(
        overflow_nullifier,
        0x19ab7b603299a71e284d8871c0400dfbf94bdf092fbb4e62065779c367bfa653,
    );
    assert_eq(comm_out, 0xf92dc8dc9c50429014208f468fd8e06a83062b2a2d0d5349dd497f9fe3c6be);
}
