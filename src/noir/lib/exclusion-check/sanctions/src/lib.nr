pub mod ordered_mt;
pub mod types;
pub mod param_commit;

use crate::ordered_mt::{ordered_mt_non_membership, ordered_mt_verify_inclusion};
use poseidon::poseidon2::Poseidon2;
use utils::tests::DG1Builder;

use types::{
    SanctionsOrderedMerkleTreeInclusionProof, SanctionsOrderedMerkleTreeProof,
    SanctionsOrderedMerkleTreeProofs,
};

use utils::{
    array_concat_as_field,
    constants::{ASCII_CODE_FOR_LESS_THAN, PASSPORT_MRZ_NAME_LENGTH},
    find_subarray_index,
    find_subarray_index_after_index,
    get_dob_from_mrz,
    get_document_number_from_mrz,
    get_name_from_mrz,
    get_nationality_from_mrz,
    get_yob_from_mrz,
    types::{DG1Data, MRZDOB, MRZDocumentNumber, MRZName, MRZNationality, MRZYOB},
    u8_array_to_fields,
};

/// Get the 3 possible last name + first name combinations from the MRZ.
///
/// This is necessary as the actual first name could be splitted into multiple parts
/// by the < character, e.g. Jean-Pierre -> JEAN<PIERRE<<<<...
///
/// # Arguments
///
/// * `dg1` - The DG1 of the passport or ID card
///
/// # Returns
///
/// A tuple of the 3 most likely last name + first name combinations
pub fn get_last_name_and_first_name_from_mrz(dg1: DG1Data) -> (MRZName, MRZName, MRZName) {
    // Gets the whole name from the MRZ
    let full_name = get_name_from_mrz(dg1);
    // << is the separator between the last name and the first name
    // Everything before is the last name, everything after is the first name, middle names, and other given names
    let full_name_separator = [ASCII_CODE_FOR_LESS_THAN, ASCII_CODE_FOR_LESS_THAN];
    // < is the separator between any given name or as a replacement for spaces, hyphens, apostrophes, etc.
    // making first name parts indistinguishable from multiple separate given names
    // (e.g. Jean-Pierre Dupont -> DUPONT<<JEAN<PIERRE<<<<..., vs John Miller Doe -> DOE<<JOHN<MILLER<<<....)
    let single_name_separator = [ASCII_CODE_FOR_LESS_THAN];
    // Gets the index of where the last name ends (i.e. where we can find the first <<)
    let last_name_end_index = find_subarray_index(full_name_separator, full_name);
    // Make sure the last name end index is valid
    assert_eq(
        full_name[last_name_end_index],
        ASCII_CODE_FOR_LESS_THAN,
        "Invalid index for last name end",
    );
    assert_eq(
        full_name[last_name_end_index + 1],
        ASCII_CODE_FOR_LESS_THAN,
        "Invalid index for last name end",
    );
    // Gets the index of where the first given name starts (i.e. after the <<)
    let first_name_start_index = last_name_end_index + full_name_separator.len();

    // Gets the index of where the second given name (or the second part of the first name) starts
    let second_name_start_index = find_subarray_index_after_index(
        single_name_separator,
        full_name,
        first_name_start_index,
    )
        + 1;
    // Note: we don't check if the character after is not < as there might not be a second given name (e.g. John Doe -> DOE<<JOHN<<<<....)
    assert(
        second_name_start_index > first_name_start_index,
        "Second name start index must be after first name start index",
    );
    // We check that the first given name is only latin letters, so no <
    for i in 0..PASSPORT_MRZ_NAME_LENGTH {
        if (i >= first_name_start_index) & (i < second_name_start_index - 1) {
            assert(
                full_name[i] != ASCII_CODE_FOR_LESS_THAN,
                "First given name contains unexpected characters",
            );
        }
    }
    // If the second_name_start_index is equal to PASSPORT_MRZ_NAME_LENGTH then it means
    // the first give name is taking all the available length and might be truncated
    if (second_name_start_index < PASSPORT_MRZ_NAME_LENGTH) {
        // Checking the separator is there at the expected index
        assert_eq(
            full_name[second_name_start_index - 1],
            ASCII_CODE_FOR_LESS_THAN,
            "Separator not found between first and second name",
        );
        // If we get a < here, then all the following characters must be <
        if (full_name[second_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if i > second_name_start_index {
                    assert_eq(
                        full_name[i],
                        ASCII_CODE_FOR_LESS_THAN,
                        "Invalid index for second name start",
                    );
                }
            }
        }
    }

    // Gets the index of where the third given name (or the third part of the first name) starts
    let third_name_start_index = find_subarray_index_after_index(
        single_name_separator,
        full_name,
        second_name_start_index,
    )
        + 1;
    // Check if not already beyond the MRZ limits
    if (second_name_start_index < PASSPORT_MRZ_NAME_LENGTH) {
        // Note: we don't check if the character after is not < as there might not be a third given name (e.g. John Miller Doe -> DOE<<JOHN<MILLER<<<....)
        assert(
            third_name_start_index > second_name_start_index,
            "Third name start index must be after second name start index",
        );
        // Now that we know third_name_start_index, we can go back to check the second name validity
        // if it is there
        if (full_name[second_name_start_index] != ASCII_CODE_FOR_LESS_THAN) {
            // We check that the second given name is only latin letters, so no <
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if (i >= second_name_start_index) & (i < third_name_start_index - 1) {
                    assert(
                        full_name[i] != ASCII_CODE_FOR_LESS_THAN,
                        "Second given name contains unexpected characters",
                    );
                }
            }
        }
    }
    // If the third_name_start_index is equal to PASSPORT_MRZ_NAME_LENGTH then it means
    // the second give name is taking all the remaining length and might be truncated
    if (third_name_start_index < PASSPORT_MRZ_NAME_LENGTH) {
        // Checking the separator is there at the expected index
        assert_eq(
            full_name[third_name_start_index - 1],
            ASCII_CODE_FOR_LESS_THAN,
            "Separator not found between second and third name",
        );
        // If we get a < here, then all the following characters must be <
        if (full_name[third_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if i > third_name_start_index {
                    assert_eq(
                        full_name[i],
                        ASCII_CODE_FOR_LESS_THAN,
                        "Invalid index for third name start",
                    );
                }
            }
        }
    }

    // Gets the index of where the fourth given name (or the fourth part of the first name) starts
    let fourth_name_start_index = find_subarray_index_after_index(
        single_name_separator,
        full_name,
        third_name_start_index,
    )
        + 1;
    // Check if not already beyond the MRZ limits
    if (third_name_start_index < PASSPORT_MRZ_NAME_LENGTH) {
        // Note: we don't check if the character after is not < as there might not be a fourth given name (e.g. John Miller Doe -> DOE<<JOHN<MILLER<<<....)
        assert(
            fourth_name_start_index > third_name_start_index,
            "Fourth name start index must be after third name start index",
        );
        // Now that we know fourth_name_start_index, we can go back to check the third name validity
        // if it is there
        if (full_name[third_name_start_index] != ASCII_CODE_FOR_LESS_THAN) {
            // We check that the third given name is only latin letters, so no <
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if (i >= third_name_start_index) & (i < fourth_name_start_index - 1) {
                    assert(
                        full_name[i] != ASCII_CODE_FOR_LESS_THAN,
                        "Third given name contains unexpected characters",
                    );
                }
            }
        }
    }
    // If the fourth_name_start_index is equal to PASSPORT_MRZ_NAME_LENGTH then it means
    // the third give name is taking all the remaining length and might be truncated
    if (fourth_name_start_index < PASSPORT_MRZ_NAME_LENGTH) {
        // Checking the separator is there at the expected index
        assert_eq(
            full_name[fourth_name_start_index - 1],
            ASCII_CODE_FOR_LESS_THAN,
            "Invalid index for fourth name start",
        );
        // If we get a < here, then all the following characters must be <
        if (full_name[fourth_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if i > fourth_name_start_index {
                    assert_eq(
                        full_name[i],
                        ASCII_CODE_FOR_LESS_THAN,
                        "Invalid index for fourth name start",
                    );
                }
            }
        }
    }

    // Last name + whatever comes before the first < (could be a whole first name or a partial first name,
    // e.g. Jean-Pierre Dupont -> DUPONT<<JEAN<PIERRE<<<<..., only DUPONT<<JEAN<<<... would be considered here)
    let name_1 = if second_name_start_index < PASSPORT_MRZ_NAME_LENGTH {
        // Implicitly fills the rest with <
        let mut result = [ASCII_CODE_FOR_LESS_THAN; PASSPORT_MRZ_NAME_LENGTH];
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            // Push characters from the original MRZ name up until the second <
            if i < second_name_start_index {
                result[i] = full_name[i];
            }
        }
        result
    } else {
        full_name
    };
    // Last name + whatever comes before the second < (could be a whole first name or a partial first name, less likely to be partial here,
    // e.g. Jean-Pierre-Martin Dupont -> DUPONT<<JEAN<PIERRE<MARTIN<<<<..., only DUPONT<<JEAN<PIERRE<<<... would be considered here)
    let name_2 = if third_name_start_index < PASSPORT_MRZ_NAME_LENGTH {
        // Implicitly fills the rest with <
        let mut result = [ASCII_CODE_FOR_LESS_THAN; PASSPORT_MRZ_NAME_LENGTH];
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            // Push characters from the original MRZ name up until the second <
            if i < third_name_start_index {
                result[i] = full_name[i];
            }
        }
        result
    } else {
        full_name
    };
    // Last name + whatever comes before the third < (this should cover most possible first names with apostrophes, hyphens or other characters replaced by <)
    let name_3 = if fourth_name_start_index < PASSPORT_MRZ_NAME_LENGTH {
        // Implicitly fills the rest with <
        let mut result = [ASCII_CODE_FOR_LESS_THAN; PASSPORT_MRZ_NAME_LENGTH];
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            // Push characters from the original MRZ name up until the third <
            if i < fourth_name_start_index {
                result[i] = full_name[i];
            }
        }
        result
    } else {
        full_name
    };
    (name_1, name_2, name_3)
}

/// The Sanctions sparse merkle trees
/// This is a collection of the three trees that are used to check the Sanctions exclusion
/// for passports and ID cards
///
/// The trees are:
/// 1. Last name + first name
/// 2. Passport No and Nationality
/// 3. Last name + first name and DOB
/// 4. Last name + first name and YOB
pub struct SanctionsSparseMerkleTrees {
    pub tree: Field,
}

impl SanctionsSparseMerkleTrees {
    /**
     * Note: default currently using the values created in our testing implementation
     */
    pub fn default() -> Self {
        Self { tree: 0x1079bc5626177edfe7be9c9f7ff8d98715d57838af41dbdb657d0d539589d562 }
    }

    pub fn root(self: Self) -> Field {
        self.tree
    }
}

impl SanctionsSparseMerkleTrees {
    /// Check the Sanctions exclusion for a given DG1
    ///
    /// # Arguments
    ///
    /// * `dg1` - The DG1 of the passport or ID card
    /// * `proofs` - The proofs for the Sanctions sparse merkle trees
    pub fn check_sanctions_exclusion(
        self: Self,
        dg1: DG1Data,
        proofs: SanctionsOrderedMerkleTreeProofs,
        is_strict: bool,
    ) {
        // Calculate the hashes
        let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
        let dob: MRZDOB = get_dob_from_mrz(dg1);
        let yob: MRZYOB = get_yob_from_mrz(dg1);
        let document_number: MRZDocumentNumber = get_document_number_from_mrz(dg1);
        let nationality: MRZNationality = get_nationality_from_mrz(dg1);

        let name_hash_1: Field =
            Poseidon2::hash(u8_array_to_fields(name_1), PASSPORT_MRZ_NAME_LENGTH);
        let name_hash_2: Field =
            Poseidon2::hash(u8_array_to_fields(name_2), PASSPORT_MRZ_NAME_LENGTH);
        let name_hash_3: Field =
            Poseidon2::hash(u8_array_to_fields(name_3), PASSPORT_MRZ_NAME_LENGTH);

        let passport_no_and_nationality = array_concat_as_field(document_number, nationality);
        let passport_no_and_nationality_hash_1: Field = Poseidon2::hash(
            passport_no_and_nationality,
            passport_no_and_nationality.len(),
        );

        let (name_and_dob_1, name_and_dob_2, name_and_dob_3) = (
            array_concat_as_field(name_1, dob), array_concat_as_field(name_2, dob),
            array_concat_as_field(name_3, dob),
        );
        let name_and_dob_hash_1: Field = Poseidon2::hash(name_and_dob_1, name_and_dob_1.len());
        let name_and_dob_hash_2: Field = Poseidon2::hash(name_and_dob_2, name_and_dob_2.len());
        let name_and_dob_hash_3: Field = Poseidon2::hash(name_and_dob_3, name_and_dob_3.len());

        let (name_and_yob_1, name_and_yob_2, name_and_yob_3) = (
            array_concat_as_field(name_1, yob), array_concat_as_field(name_2, yob),
            array_concat_as_field(name_3, yob),
        );
        let name_and_yob_hash_1: Field = Poseidon2::hash(name_and_yob_1, name_and_yob_1.len());
        let name_and_yob_hash_2: Field = Poseidon2::hash(name_and_yob_2, name_and_yob_2.len());
        let name_and_yob_hash_3: Field = Poseidon2::hash(name_and_yob_3, name_and_yob_3.len());

        // If the strict mode is enabled, we need to check against just the names
        // which has a higher likelihood of matching against an entry of the sanctions
        // hence why it should be explicitly enabled by the prover
        if (is_strict) {
            // Check against the names (last name + first name)
            ordered_mt_non_membership(self.tree, name_hash_1, proofs.name_proof);
            ordered_mt_non_membership(self.tree, name_hash_2, proofs.name_proof);
            ordered_mt_non_membership(self.tree, name_hash_3, proofs.name_proof);
        }

        // Check against the passport no and nationality
        ordered_mt_non_membership(
            self.tree,
            passport_no_and_nationality_hash_1,
            proofs.passport_no_and_nationality_proof,
        );
        // Check against the names and DOB
        ordered_mt_non_membership(self.tree, name_and_dob_hash_1, proofs.name_and_dob_proof);
        ordered_mt_non_membership(self.tree, name_and_dob_hash_2, proofs.name_and_dob_proof);
        ordered_mt_non_membership(self.tree, name_and_dob_hash_3, proofs.name_and_dob_proof);
        // Check against the names and YOB
        ordered_mt_non_membership(self.tree, name_and_yob_hash_1, proofs.name_and_yob_proof);
        ordered_mt_non_membership(self.tree, name_and_yob_hash_2, proofs.name_and_yob_proof);
        ordered_mt_non_membership(self.tree, name_and_yob_hash_3, proofs.name_and_yob_proof);
    }
}

#[test]
fn test_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // Should retrieve the last name and first given name
    assert_eq(name_1, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should retrieve the last name, the first and second given (or middle) names
    assert_eq(name_2, "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should be the same as above since there's nothing beyond the middle name
    assert_eq(name_3, "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
}

#[test]
fn test_long_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<JOHN<MILLER<JUNIOR<THE<SECOND<<<<<".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<JOHN<MILLER<JUNIOR<THE<SECOND<<<<<".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // Should retrieve the last name and first given name
    assert_eq(name_1, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should retrieve the last name, the first and second given (or middle) names
    assert_eq(name_2, "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should retrieve the last name, the first, second and third given names
    assert_eq(name_3, "DOE<<JOHN<MILLER<JUNIOR<<<<<<<<<<<<<<<<".as_bytes());
}

#[test]
fn test_short_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // They should all return the same as there is only one give name
    assert_eq(name_1, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_2, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_3, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
}

#[test]
fn test_full_mrz_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<JOHN<MILLER<JUNIOR<THE<SECOND<EMPE".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<JOHN<MILLER<JUNIOR<THE<SECOND<EMPE".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // Should retrieve the last name and first given name
    assert_eq(name_1, "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should retrieve the last name, the first and second given (or middle) names
    assert_eq(name_2, "DOE<<JOHN<MILLER<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    // Should retrieve the last name, the first, second and third given names
    assert_eq(name_3, "DOE<<JOHN<MILLER<JUNIOR<<<<<<<<<<<<<<<<".as_bytes());
}

#[test]
fn test_long_first_given_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<SUPERCALIFRAGILISTICEXPIALIDOCIOUS".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<SUPERCALIFRAGILISTICEXPIALIDOCIOUS".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // This first given name is super long, so no space for other names
    // All of three name combinations return the full name from the MRZ
    assert_eq(name_1, "DOE<<SUPERCALIFRAGILISTICEXPIALIDOCIOUS".as_bytes());
    assert_eq(name_2, "DOE<<SUPERCALIFRAGILISTICEXPIALIDOCIOUS".as_bytes());
    assert_eq(name_3, "DOE<<SUPERCALIFRAGILISTICEXPIALIDOCIOUS".as_bytes());
}

#[test]
fn test_long_second_given_name_retrieval_from_dg1() {
    let passport_no = "123456789".as_bytes();
    let dob = "900112".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<SUPERCALIFRAGILISTIC<EXPIALIDOCIOU".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let full_name = get_name_from_mrz(dg1);
    // Should be the same full name as initialized above
    assert_eq(full_name, "DOE<<SUPERCALIFRAGILISTIC<EXPIALIDOCIOU".as_bytes());

    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);
    // The first name and second name take all the space, so no room for a third
    // The first name combination returns just the last name and first given name
    assert_eq(name_1, "DOE<<SUPERCALIFRAGILISTIC<<<<<<<<<<<<<<".as_bytes());
    // while the second combination returns the full MRZ name
    assert_eq(name_2, "DOE<<SUPERCALIFRAGILISTIC<EXPIALIDOCIOU".as_bytes());
    // and so does the third since there's no room for a third given name
    assert_eq(name_3, "DOE<<SUPERCALIFRAGILISTIC<EXPIALIDOCIOU".as_bytes());
}

#[test]
fn test_non_inclusion_of_dg1() {
    // Provide the non inclusion proofs for an empty dg1
    // name = 'Doe<<John<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<',
    // dob = '900112',
    // year = '90',
    // passport no = 123456789
    // country = United Kingdom

    let passport_no = [49, 50, 51, 52, 53, 54, 55, 56, 57];
    let country = [71, 66, 82];
    let name = [
        68, 111, 101, 60, 60, 74, 111, 104, 110, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    ];

    let dob = [57, 48, 48, 49, 49, 50];

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: SanctionsSparseMerkleTrees = SanctionsSparseMerkleTrees::default();

    let name_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 4280651730102752895868097147365593630370914047050049990849625853600982892726,
            leaf_index: 24613,
            sibling_path: [
                4280612885042980187974231780384420456070649735062637347326943750102781194513,
                11295924195820056241398187534137019418657742636797297669674784457288167494079,
                14524272796401237678001636577212859062131007384875308855580619793919236100710,
                5809679630419309691502461005067284044585361435644304719255171411417234396502,
                20289652722227918755828879752509465364307243989479092424423217956008154358079,
                19087032881200345720940376666975103804222458816421385076715145416718655917949,
                8017889431952571189494080958004689727238285370191232345902199564987232811931,
                3821556461277087128358826603648743152730538691363096231816900232623540823546,
                2959276721759474934477218128612869682097552010653031457401567236004635692369,
                15045183741572774568468663966460595129873020549734600179366176472295346749858,
                12281833404048243194685268342065302835436896073830032788749886206208513889548,
                4610807531753795933723487203199065889630782627611808415163802025285863095535,
                11998808275280285280332222762316934822915585620970001814354250302107164362245,
                1289593655745440005360907472683380093264674864991929526404603463638425713257,
                20463071521547961416057871386537637823074153304341299592105687020838665714767,
                1422994654356092138536825598618436060486605061183646776786639611356403240263,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 4280795519001352838791436431064110826592645585200170178534428182873904946729,
            leaf_index: 24614,
            sibling_path: [
                4281039773715339958484843482919149360225380388767690703923167923703725776655,
                1520554603635321140119746476459370654864973816165795100730588689092149733234,
                14524272796401237678001636577212859062131007384875308855580619793919236100710,
                5809679630419309691502461005067284044585361435644304719255171411417234396502,
                20289652722227918755828879752509465364307243989479092424423217956008154358079,
                19087032881200345720940376666975103804222458816421385076715145416718655917949,
                8017889431952571189494080958004689727238285370191232345902199564987232811931,
                3821556461277087128358826603648743152730538691363096231816900232623540823546,
                2959276721759474934477218128612869682097552010653031457401567236004635692369,
                15045183741572774568468663966460595129873020549734600179366176472295346749858,
                12281833404048243194685268342065302835436896073830032788749886206208513889548,
                4610807531753795933723487203199065889630782627611808415163802025285863095535,
                11998808275280285280332222762316934822915585620970001814354250302107164362245,
                1289593655745440005360907472683380093264674864991929526404603463638425713257,
                20463071521547961416057871386537637823074153304341299592105687020838665714767,
                1422994654356092138536825598618436060486605061183646776786639611356403240263,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    // All 3 proofs
    // Passport
    let passport_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18675171674992009614613967950134235111310310154757415139272923776809222053631,
            leaf_index: 107881,
            sibling_path: [
                18674715260203880852824743707608376385350189999936977334562421885419294099316,
                3158080054576463709639977175516985002324479592230493784476371896402816298210,
                15283579050714281639857456252450917773010556169871923821018122833900915726435,
                13498199792214298578344399105370519425999159737256706682216365777022902921515,
                12437164939864867147364661156838645158352298132013580432455699235945334868866,
                10709720678297675295238622192361684555031388717723098543827757376088885118253,
                7253078565744819172476780590015015671277521747812181506253602990418968364421,
                19104238930495209422049479369507559497177008863819989875075524017584844609339,
                3143139554400101554920495908340921003088395928697787148460390005767365620310,
                17782105080258009158052042817220061784119823215300771297828167844977621795524,
                18812403797937730695351982321717166130877840987550535065349060311124012869201,
                975778644872364263438177481563136194941668540190942662154597273444501139286,
                6400626317900429842499317236071339229208011959030764738692134314563927092247,
                11231310364016593613137633767139496697471082526007519066225768337227031394965,
                8778059876480737609203125512523392064727288999875875362168816750616041721498,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18675821607800233414529613648951130622711370689642617075616882486370590141673,
            leaf_index: 107882,
            sibling_path: [
                18675829295852343244537182675239122328155699682271639274700277812403927806268,
                21457388494033844730516804353854623859965298291448645672213893625211960480618,
                15283579050714281639857456252450917773010556169871923821018122833900915726435,
                13498199792214298578344399105370519425999159737256706682216365777022902921515,
                12437164939864867147364661156838645158352298132013580432455699235945334868866,
                10709720678297675295238622192361684555031388717723098543827757376088885118253,
                7253078565744819172476780590015015671277521747812181506253602990418968364421,
                19104238930495209422049479369507559497177008863819989875075524017584844609339,
                3143139554400101554920495908340921003088395928697787148460390005767365620310,
                17782105080258009158052042817220061784119823215300771297828167844977621795524,
                18812403797937730695351982321717166130877840987550535065349060311124012869201,
                975778644872364263438177481563136194941668540190942662154597273444501139286,
                6400626317900429842499317236071339229208011959030764738692134314563927092247,
                11231310364016593613137633767139496697471082526007519066225768337227031394965,
                8778059876480737609203125512523392064727288999875875362168816750616041721498,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_dob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 10984199612734337474950014062007467900423567078840448731896427917771883937989,
            leaf_index: 63427,
            sibling_path: [
                10983890538359762294792838192134201708058746134477588589533771802188736285180,
                11098101516497257943067080535067929802059204162441756242266551195414858355723,
                15862836228849298131672379082879856160921263670126269939350119086311288113284,
                8450507286091333357723761572942960242461675072027924711708359029130074567348,
                6616926585425421544033023050308597850422424500754273573520294269464316842718,
                3337108672350020148244478000009056313649437849014563593523851504345178456694,
                19173015384570487255057556799372884677409978739649546350962528994528893952886,
                7514628370335471156998001403932218902118985266253118454027601860507822279933,
                3004539909878201853991700098823335049293640684406940657171523489640426844764,
                1839200043933206312092276836474746812669778259848281778554119689075165722493,
                13893855865773077544886342336537499567528189553303135228962372700794120640493,
                16933197077681040503020069837512653198491234070415630336504202236908233207459,
                18688701205747870309841839683133242943089874847211932191647240081583177348154,
                5727750992012521369321237547515795806941370046270210938101202447460876514407,
                4254846947511495093749461761353203819771426995975429033606910203470209946225,
                12683424646142908310770648065228460697610402891620652519422343579906382312231,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 10984371415775900955274405826672228833819299875444992185237512186315486258143,
            leaf_index: 63428,
            sibling_path: [
                10984891399624235239132092529128645900871468462638465791731227511419893107457,
                14331076054574287214323918419505611614220929098706788416443834844186049021969,
                994972923618461893193619000930076086914754095795045307926016922813983338638,
                8450507286091333357723761572942960242461675072027924711708359029130074567348,
                6616926585425421544033023050308597850422424500754273573520294269464316842718,
                3337108672350020148244478000009056313649437849014563593523851504345178456694,
                19173015384570487255057556799372884677409978739649546350962528994528893952886,
                7514628370335471156998001403932218902118985266253118454027601860507822279933,
                3004539909878201853991700098823335049293640684406940657171523489640426844764,
                1839200043933206312092276836474746812669778259848281778554119689075165722493,
                13893855865773077544886342336537499567528189553303135228962372700794120640493,
                16933197077681040503020069837512653198491234070415630336504202236908233207459,
                18688701205747870309841839683133242943089874847211932191647240081583177348154,
                5727750992012521369321237547515795806941370046270210938101202447460876514407,
                4254846947511495093749461761353203819771426995975429033606910203470209946225,
                12683424646142908310770648065228460697610402891620652519422343579906382312231,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_yob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 21803835190397426224290711267479180422749555830927701354253482287436278289470,
            leaf_index: 125970,
            sibling_path: [
                21804113507305188010759451472530030817263328814056426225528540699128147600261,
                15183260586177496695569267901917055872705943160217070318458058695869088355856,
                7747898697346228712377505775047675707831860550795331145716782669698367306987,
                777745875765028585935485167298331402082347752464539283810258879412392284611,
                7322464027723859587120787660808038190995283139151333822846383157559270683278,
                16357247245330057721739153999025932779352051739183284578555560605960009695222,
                719519666096846707134667945988706950114536138990496741435383330944893614865,
                14951186966813761708525665426507218730418044390732253717465670194563566364608,
                12136530068178324334496557972839604489922150273379955330145961245007358153242,
                9991422318454521821128338471606641979259237074108962608028352627428394523821,
                8420452276405820892235403482629645259266091883096354161332690373973590516306,
                19111779572475649082383959434083598312953195743436125218951423886111744463100,
                5894139036143562089612233756205231544611692010506775540918923829608719739507,
                1203294498575717254692794792695306993026766706902650640017553717055079299678,
                19424422082721370925316230216705868791935161432859181533168965137582623400267,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 21804113507305188010759451472530030817263328814056426225528540699128147600261,
            leaf_index: 125971,
            sibling_path: [
                21803835190397426224290711267479180422749555830927701354253482287436278289470,
                15183260586177496695569267901917055872705943160217070318458058695869088355856,
                7747898697346228712377505775047675707831860550795331145716782669698367306987,
                777745875765028585935485167298331402082347752464539283810258879412392284611,
                7322464027723859587120787660808038190995283139151333822846383157559270683278,
                16357247245330057721739153999025932779352051739183284578555560605960009695222,
                719519666096846707134667945988706950114536138990496741435383330944893614865,
                14951186966813761708525665426507218730418044390732253717465670194563566364608,
                12136530068178324334496557972839604489922150273379955330145961245007358153242,
                9991422318454521821128338471606641979259237074108962608028352627428394523821,
                8420452276405820892235403482629645259266091883096354161332690373973590516306,
                19111779572475649082383959434083598312953195743436125218951423886111744463100,
                5894139036143562089612233756205231544611692010506775540918923829608719739507,
                1203294498575717254692794792695306993026766706902650640017553717055079299678,
                19424422082721370925316230216705868791935161432859181533168965137582623400267,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let smt_proofs = SanctionsOrderedMerkleTreeProofs {
        name_proof: name_proof,
        passport_no_and_nationality_proof: passport_proof,
        name_and_dob_proof: name_and_dob_proof,
        name_and_yob_proof: name_and_yob_proof,
    };

    trees.check_sanctions_exclusion(dg1, smt_proofs, true);
}

#[test]
fn test_non_inclusion_of_german_dg1() {
    // Provide the non inclusion proofs for an empty dg1
    // name = 'MUELLER<<JOHANNES<<<<<<<<<<<<<<<<<<<<<<',
    // dob = '860226',
    // year = '86',
    // passport no = 123456789
    // country = Germany

    let passport_no = "123456789".as_bytes();
    // The MRZ country is D<< while the standard Alpha3 code for Germany is DEU
    // The actual sanctions list will be using DEU rather than D<<, but the circuit
    // should make the conversion from D<< to DEU when the country is retrieved from the MRZ
    let country = "D<<".as_bytes();
    let name = "MUELLER<<JOHANNES<<<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dob = "860226".as_bytes();

    let dg1: [u8; 95] = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: SanctionsSparseMerkleTrees = SanctionsSparseMerkleTrees::default();

    let name_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 16847615597941925683125829487704639912742480801748637799512831103621180199493,
            leaf_index: 97290,
            sibling_path: [
                16847877387895272008133175339196796799982204440531370830285746768266245745917,
                20738615942887587179820614498293914798170760129029032420224729924363224820489,
                7934351455666818703350667503633202511798777514023640385401455115272196262675,
                18226728619241820879758050983022628282118705126901793488087231438911850356745,
                10426708575722631932416641850894056277069752343200912215469510513171638234279,
                6693654048951829055580293402483604326487319239991479760215928505520847437952,
                3787833391698726257323505816586002478030057960143760960709262614758340673673,
                7615694177853296778597904232210380818653449125215306146719004503178504234197,
                12072757524577007918261690148512417654817145655500352031675346135269104649202,
                8942353665733650144372856331587377383358982804829906936491052181975904675589,
                8246193198671116757882191937356211158652082159611407430020314029097620997202,
                11566611065835798900593388280634976731841862812064604353877294433544908174166,
                10185195751024778655897176187932042772709314859570556475448920338841580517408,
                13506773201853095331737715714796966985085210404911265152183499454556611289715,
                6509362040180774212851105362046062603617926179819297625570081110663018609878,
                18505416075518868536144873598483330416428865263621881727010127303419714436280,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 16847877387895272008133175339196796799982204440531370830285746768266245745917,
            leaf_index: 97291,
            sibling_path: [
                16847615597941925683125829487704639912742480801748637799512831103621180199493,
                20738615942887587179820614498293914798170760129029032420224729924363224820489,
                7934351455666818703350667503633202511798777514023640385401455115272196262675,
                18226728619241820879758050983022628282118705126901793488087231438911850356745,
                10426708575722631932416641850894056277069752343200912215469510513171638234279,
                6693654048951829055580293402483604326487319239991479760215928505520847437952,
                3787833391698726257323505816586002478030057960143760960709262614758340673673,
                7615694177853296778597904232210380818653449125215306146719004503178504234197,
                12072757524577007918261690148512417654817145655500352031675346135269104649202,
                8942353665733650144372856331587377383358982804829906936491052181975904675589,
                8246193198671116757882191937356211158652082159611407430020314029097620997202,
                11566611065835798900593388280634976731841862812064604353877294433544908174166,
                10185195751024778655897176187932042772709314859570556475448920338841580517408,
                13506773201853095331737715714796966985085210404911265152183499454556611289715,
                6509362040180774212851105362046062603617926179819297625570081110663018609878,
                18505416075518868536144873598483330416428865263621881727010127303419714436280,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    // All 3 proofs
    // Passport
    let passport_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 17678483488934989303041571921721254879047474800165078075593658906956492165875,
            leaf_index: 102138,
            sibling_path: [
                17679946430902534397335637626482439472280994668445251224471281429426312031564,
                6610364792281795014260198959345927065458104257038120310051615204099271167669,
                17071394433281339728804309560474070325609424089502012712832817855000904978973,
                19355669467201825895643555569013894855999173917948225057431610936094979955746,
                16296033160958258734611804305347521858475063132264995215727002013666576551012,
                11717415999460740990846800775099227879379079213525134723777832082814980505385,
                4241799147158858255932669966019652298340721472328336361520817435246788733810,
                7323497735887632467787795931246691068698443190396777872209647077647602314351,
                4063142677512455867333949309601444422523388959715935223700041568090450676893,
                20113700685198051252292061510192628999974095419222701226159437217360416927468,
                3033748130007893061293755471434174522750346687411047617054175784566019413975,
                8622436038172754132964946638614688758399521010810825185392502116587455745994,
                17163975429570242171544934257843857250141742961820808930562387489363740278690,
                2950097410735154484653176102593622911187853351481671099976888249055875593695,
                8778059876480737609203125512523392064727288999875875362168816750616041721498,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 17679946430902534397335637626482439472280994668445251224471281429426312031564,
            leaf_index: 102139,
            sibling_path: [
                17678483488934989303041571921721254879047474800165078075593658906956492165875,
                6610364792281795014260198959345927065458104257038120310051615204099271167669,
                17071394433281339728804309560474070325609424089502012712832817855000904978973,
                19355669467201825895643555569013894855999173917948225057431610936094979955746,
                16296033160958258734611804305347521858475063132264995215727002013666576551012,
                11717415999460740990846800775099227879379079213525134723777832082814980505385,
                4241799147158858255932669966019652298340721472328336361520817435246788733810,
                7323497735887632467787795931246691068698443190396777872209647077647602314351,
                4063142677512455867333949309601444422523388959715935223700041568090450676893,
                20113700685198051252292061510192628999974095419222701226159437217360416927468,
                3033748130007893061293755471434174522750346687411047617054175784566019413975,
                8622436038172754132964946638614688758399521010810825185392502116587455745994,
                17163975429570242171544934257843857250141742961820808930562387489363740278690,
                2950097410735154484653176102593622911187853351481671099976888249055875593695,
                8778059876480737609203125512523392064727288999875875362168816750616041721498,
                5524398138400450273071411981583832211754903347029965063071955359164710565567,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_dob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 5240759408207838678544692133887790386144583197247728150887913006693101860408,
            leaf_index: 30140,
            sibling_path: [
                5241706441765909250871422924725078949625321825638467420885267645523233061819,
                12909438770350999513558946415805956629909722893793155870592437228394097789863,
                8747639625874857576495286740092848012934551624155345310179782150251763827379,
                809941564982723887500668833944388189237444757294371578932051156430690169289,
                4355393481304024379914137762407181619548984265395524317021563606165058960000,
                4068559166882210993688710649521847973903182238526796588236379150593418468563,
                5267607491316081116788470660505233636300543567081525988662130871869564251453,
                7923765418259021625262771184721745457198038099878664723496398321017969139229,
                13914515325737680446731533719514909601547616914103895956502554500107234817915,
                12683354249121491855986808261950371018184773839934110544741136599167365959282,
                16392022409439566929771168397930111825627965262667498443736694766881204248206,
                996275240114421564095093017802820206950975604601745692388501959898689301281,
                6862575599835914984331704104138913066088276512691183982695804777759334493606,
                1289593655745440005360907472683380093264674864991929526404603463638425713257,
                20463071521547961416057871386537637823074153304341299592105687020838665714767,
                1422994654356092138536825598618436060486605061183646776786639611356403240263,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 5241706441765909250871422924725078949625321825638467420885267645523233061819,
            leaf_index: 30141,
            sibling_path: [
                5240759408207838678544692133887790386144583197247728150887913006693101860408,
                12909438770350999513558946415805956629909722893793155870592437228394097789863,
                8747639625874857576495286740092848012934551624155345310179782150251763827379,
                809941564982723887500668833944388189237444757294371578932051156430690169289,
                4355393481304024379914137762407181619548984265395524317021563606165058960000,
                4068559166882210993688710649521847973903182238526796588236379150593418468563,
                5267607491316081116788470660505233636300543567081525988662130871869564251453,
                7923765418259021625262771184721745457198038099878664723496398321017969139229,
                13914515325737680446731533719514909601547616914103895956502554500107234817915,
                12683354249121491855986808261950371018184773839934110544741136599167365959282,
                16392022409439566929771168397930111825627965262667498443736694766881204248206,
                996275240114421564095093017802820206950975604601745692388501959898689301281,
                6862575599835914984331704104138913066088276512691183982695804777759334493606,
                1289593655745440005360907472683380093264674864991929526404603463638425713257,
                20463071521547961416057871386537637823074153304341299592105687020838665714767,
                1422994654356092138536825598618436060486605061183646776786639611356403240263,
                5042802630641403920974617864550092647133845650337096664008357172644603542641,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_yob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 13520906526882975260047628088903941351233487524184204507586188205041172984379,
            leaf_index: 78127,
            sibling_path: [
                13520724679456254784797560335269264600349770909588346167124667588496439306404,
                17547589527675046378319306460531428735665391508875015109725967933124858235815,
                21187874563960972172132212243982351888321958784467832732107416620885465663293,
                17412349481612008473599018071201954951652208442042233557141956543419955016603,
                4237719680092726515096020941952334376456864322736058146516372239662062375732,
                16472513679111540967394402975143038059091298152665673346714689223553472234287,
                19364283825519223179855573016527226463407629885813299010244940361694899511816,
                15474533666105315172230481702171583413726090401969160141557471817446587076772,
                12701469573042955669020206371345832346971668768927103738699796553057859670219,
                5493352740730362047381281923166437732975845919764419661994940643255887382522,
                9957224299722119231017884371911476631197313450320907613027817857290900680509,
                9330898613678787112583412239682208712804129108827411714391241115451372892223,
                4914996564202290436991933330010169792111438356781152391199332109709063808017,
                6975960600686614968923973994538981691081144840201786785025750641323456730512,
                8112529647102085982313768090331591455064740979303453033169863395844400227744,
                18505416075518868536144873598483330416428865263621881727010127303419714436280,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 13521425026896420022203876767580951416401644784854387377332576981467843596093,
            leaf_index: 78128,
            sibling_path: [
                13521502695515903361244935247129799526672778354847082897029932877696748329337,
                21874778617145494419314935040756482361483908383156148190130692459250568863938,
                1630775939043401794425798555964679079156798480320634497582980352925516086011,
                13674628169919199171693875062206274025750924647801232451887857415952278266401,
                14250339871667550643089031542850766304410011781197874459214171871639975955140,
                16472513679111540967394402975143038059091298152665673346714689223553472234287,
                19364283825519223179855573016527226463407629885813299010244940361694899511816,
                15474533666105315172230481702171583413726090401969160141557471817446587076772,
                12701469573042955669020206371345832346971668768927103738699796553057859670219,
                5493352740730362047381281923166437732975845919764419661994940643255887382522,
                9957224299722119231017884371911476631197313450320907613027817857290900680509,
                9330898613678787112583412239682208712804129108827411714391241115451372892223,
                4914996564202290436991933330010169792111438356781152391199332109709063808017,
                6975960600686614968923973994538981691081144840201786785025750641323456730512,
                8112529647102085982313768090331591455064740979303453033169863395844400227744,
                18505416075518868536144873598483330416428865263621881727010127303419714436280,
                13926253249914318025768305966574576388866022771930728108723425567423515278435,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let smt_proofs = SanctionsOrderedMerkleTreeProofs {
        name_proof: name_proof,
        passport_no_and_nationality_proof: passport_proof,
        name_and_dob_proof: name_and_dob_proof,
        name_and_yob_proof: name_and_yob_proof,
    };

    trees.check_sanctions_exclusion(dg1, smt_proofs, true);
}

#[test]
fn test_of_sanctioned_person() {
    // Provide the non inclusion proofs for an empty dg1
    // name = 'DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<',
    // dob = '800416',
    // yob = '80',
    // passport no = 123456789
    // country = Germany

    let passport_no = "123456789".as_bytes();
    let country = "D<<".as_bytes();
    let name = "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dob = "800416".as_bytes();

    let dg1: [u8; 95] = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: SanctionsSparseMerkleTrees = SanctionsSparseMerkleTrees::default();

    // Calculate the hashes
    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);

    assert_eq(name_1, "DAVIS<<MICHAEL<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_2, "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_3, "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes());

    let name_hash_1: Field = Poseidon2::hash(u8_array_to_fields(name_1), PASSPORT_MRZ_NAME_LENGTH);
    let name_hash_2: Field = Poseidon2::hash(u8_array_to_fields(name_2), PASSPORT_MRZ_NAME_LENGTH);
    let name_hash_3: Field = Poseidon2::hash(u8_array_to_fields(name_3), PASSPORT_MRZ_NAME_LENGTH);

    let name_inclusion_proof = SanctionsOrderedMerkleTreeInclusionProof {
        // The expected sanctioned person is named Michael Davis and this hash is over that name as John is ignored in name_1
        leaf: name_hash_1,
        leaf_index: 57216,
        sibling_path: [
            9917525085591752581815867813532608282359240187823645181665529410618628728607,
            3431052744215081681480976828716737621163856748575777367910887314742006695939,
            6418727495989530780546114812036204702108953081993351128102732345932296691789,
            4328202309152572252782749175533811821007778323631966435755593379401580473415,
            20726861444826226845721201967555560732609430883832673776745974875045717710620,
            1566377984844007856960522890036561271433250771707066026007729025757416871425,
            8919930810718162038444455305732689131482152809229720072326756376903262201529,
            4377473888900364922469497989515711363185719422469298683091998969328964426541,
            8415528562129623924956380374058438721344159789817117020997022412783309148842,
            15400092816287534810408601279287358166367111014101641835629706941777609696255,
            20204514494552444033306977128660099378405396079032873609923785899109028591940,
            20683932670380062326840856559978548528259402849447456651743220626426692968064,
            5753771327376279061267265730268780521492608862716493049481745859518276863294,
            9922401542268609230781035238527393176050103844702705550601896687864179450497,
            4254846947511495093749461761353203819771426995975429033606910203470209946225,
            12683424646142908310770648065228460697610402891620652519422343579906382312231,
            5042802630641403920974617864550092647133845650337096664008357172644603542641,
            3218243980816964110015535469652973420290887819006413761652914020854170460131,
        ],
    };

    ordered_mt_verify_inclusion(trees.root(), name_inclusion_proof);
}

#[test(should_fail)]
fn test_of_sanctioned_person_with_wrong_name_combination() {
    // Provide the non inclusion proofs for an empty dg1
    // name = 'DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<',
    // dob = '800416',
    // yob = '80',
    // passport no = 123456789
    // country = Germany

    let passport_no = "123456789".as_bytes();
    let country = "D<<".as_bytes();
    let name = "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dob = "800416".as_bytes();

    let dg1: [u8; 95] = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: SanctionsSparseMerkleTrees = SanctionsSparseMerkleTrees::default();

    // Calculate the hashes
    let (name_1, name_2, name_3) = get_last_name_and_first_name_from_mrz(dg1);

    assert_eq(name_1, "DAVIS<<MICHAEL<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_2, "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes());
    assert_eq(name_3, "DAVIS<<MICHAEL<JOHN<<<<<<<<<<<<<<<<<<<<".as_bytes());

    let name_hash_1: Field = Poseidon2::hash(u8_array_to_fields(name_1), PASSPORT_MRZ_NAME_LENGTH);
    let name_hash_2: Field = Poseidon2::hash(u8_array_to_fields(name_2), PASSPORT_MRZ_NAME_LENGTH);
    let name_hash_3: Field = Poseidon2::hash(u8_array_to_fields(name_3), PASSPORT_MRZ_NAME_LENGTH);

    let name_inclusion_proof = SanctionsOrderedMerkleTreeInclusionProof {
        // The expected sanctioned person is named Michael Davis but this hash is over Michael John Davis (wrong name combination)
        leaf: name_hash_2,
        leaf_index: 57216,
        sibling_path: [
            9917525085591752581815867813532608282359240187823645181665529410618628728607,
            3431052744215081681480976828716737621163856748575777367910887314742006695939,
            6418727495989530780546114812036204702108953081993351128102732345932296691789,
            4328202309152572252782749175533811821007778323631966435755593379401580473415,
            20726861444826226845721201967555560732609430883832673776745974875045717710620,
            1566377984844007856960522890036561271433250771707066026007729025757416871425,
            8919930810718162038444455305732689131482152809229720072326756376903262201529,
            4377473888900364922469497989515711363185719422469298683091998969328964426541,
            8415528562129623924956380374058438721344159789817117020997022412783309148842,
            15400092816287534810408601279287358166367111014101641835629706941777609696255,
            20204514494552444033306977128660099378405396079032873609923785899109028591940,
            20683932670380062326840856559978548528259402849447456651743220626426692968064,
            5753771327376279061267265730268780521492608862716493049481745859518276863294,
            9922401542268609230781035238527393176050103844702705550601896687864179450497,
            4254846947511495093749461761353203819771426995975429033606910203470209946225,
            12683424646142908310770648065228460697610402891620652519422343579906382312231,
            5042802630641403920974617864550092647133845650337096664008357172644603542641,
            3218243980816964110015535469652973420290887819006413761652914020854170460131,
        ],
    };

    ordered_mt_verify_inclusion(trees.root(), name_inclusion_proof);
}
