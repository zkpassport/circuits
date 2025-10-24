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
        Self { tree: 0x06caac33440d8a83b838f07ba0e2bbe7e9889f10915efcb37396534f1feadac5 }
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
    // name = 'DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<',
    // dob = '900112',
    // year = '90',
    // passport no = 123456789
    // country = United Kingdom

    let passport_no = "123456789".as_bytes();
    let country = "GBR".as_bytes();
    let name = "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<".as_bytes();

    let dob = "900112".as_bytes();

    let dg1 = DG1Builder::new([0; 95])
        .with_document_number(passport_no)
        .with_nationality(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: SanctionsSparseMerkleTrees = SanctionsSparseMerkleTrees::default();

    let name_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 8956333565342100626175684213002399724701754566975930761671412343567175376742,
            leaf_index: 51593,
            sibling_path: [
                8956305397887706548947467917432368310894119267665310574331312227313411265134,
                1591120206616175795870232267773251984825068517407387174975635279974067926371,
                16969395441223965267956801463617438551170619544519933668094428186326013452432,
                12722416459856144664961119142750367093020138265354979344147714571102471165663,
                9877578740075321285338349967107768707558172152818712161401418075364134032914,
                9462051373244237763893674566436629662815600358438718027312965399322214905738,
                5981465055244570025758375013728857801808507541381791615023562018708670499750,
                7008611329667300025930163583922313669229510724997251198196463150192376359077,
                7430092275982209248149380709910416506860531075248379624377138719573005807557,
                2539223405343873722544228890873340306288699692440681928258626679764767852271,
                11388761669303640281268750629515116538445832677239394545218414812990178691609,
                21846682940769700317251668820007414496451237708822098701178908893455710019812,
                1128828666413400385476274889803792632277402843777785901787911744596226244699,
                10137962158573734050162686176154332483946400485913588436121049706320967897922,
                20865758332970325045263219825193635787614754990818729783792516628094684528923,
                21492147508593555798954276854884538585208918386284299128827770232157281300008,
                18603683295116425944172923198605921892107095987681914655028475372448354804282,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 8956500318397858565112995016720085659827620516307512068909343396650685795378,
            leaf_index: 51594,
            sibling_path: [
                8956528693531332551224663346512158253405203876470036151562525145332603872254,
                14271873248335483546826859233495525133684542874637762307797131009167564271404,
                16969395441223965267956801463617438551170619544519933668094428186326013452432,
                12722416459856144664961119142750367093020138265354979344147714571102471165663,
                9877578740075321285338349967107768707558172152818712161401418075364134032914,
                9462051373244237763893674566436629662815600358438718027312965399322214905738,
                5981465055244570025758375013728857801808507541381791615023562018708670499750,
                7008611329667300025930163583922313669229510724997251198196463150192376359077,
                7430092275982209248149380709910416506860531075248379624377138719573005807557,
                2539223405343873722544228890873340306288699692440681928258626679764767852271,
                11388761669303640281268750629515116538445832677239394545218414812990178691609,
                21846682940769700317251668820007414496451237708822098701178908893455710019812,
                1128828666413400385476274889803792632277402843777785901787911744596226244699,
                10137962158573734050162686176154332483946400485913588436121049706320967897922,
                20865758332970325045263219825193635787614754990818729783792516628094684528923,
                21492147508593555798954276854884538585208918386284299128827770232157281300008,
                18603683295116425944172923198605921892107095987681914655028475372448354804282,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    // All 3 proofs
    // Passport
    let passport_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18674715260203880852824743707608376385350189999936977334562421885419294099316,
            leaf_index: 107606,
            sibling_path: [
                18675821607800233414529613648951130622711370689642617075616882486370590141673,
                2235033626648116514709760861815800515299684018920358707602913096811659895942,
                11503218394556582765667268603158706079553461947258582921270239559907522184657,
                13030783494610390476541847708326394916412493839955755269662930598445000712768,
                15871034836026949006187703017243346260695067217705632182399889870144892049303,
                17881719938579283468595484433988776387863822156642722991543771082486770304156,
                4079899484453199391213323276366517467324826887275162164291483033577124778398,
                3459892850181617151077636181855551931087241222183073870271011561201101501367,
                10986774043574033481425666483322530977362443463173647690469923373199157875970,
                19728549829450393548240267325853686359476905577241337836579012539095218112131,
                14177597732799768851299709122507163976498990272990485438928664512475005943363,
                8347558843476815548091596585852118140043037940689615423266199440381484117465,
                20927667387671448242735747635641450549102902794755877140563239741610265266958,
                12746091157216926473999609111614204306845838307854234554248792507666256553013,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18675821607800233414529613648951130622711370689642617075616882486370590141673,
            leaf_index: 107607,
            sibling_path: [
                18674715260203880852824743707608376385350189999936977334562421885419294099316,
                2235033626648116514709760861815800515299684018920358707602913096811659895942,
                11503218394556582765667268603158706079553461947258582921270239559907522184657,
                13030783494610390476541847708326394916412493839955755269662930598445000712768,
                15871034836026949006187703017243346260695067217705632182399889870144892049303,
                17881719938579283468595484433988776387863822156642722991543771082486770304156,
                4079899484453199391213323276366517467324826887275162164291483033577124778398,
                3459892850181617151077636181855551931087241222183073870271011561201101501367,
                10986774043574033481425666483322530977362443463173647690469923373199157875970,
                19728549829450393548240267325853686359476905577241337836579012539095218112131,
                14177597732799768851299709122507163976498990272990485438928664512475005943363,
                8347558843476815548091596585852118140043037940689615423266199440381484117465,
                20927667387671448242735747635641450549102902794755877140563239741610265266958,
                12746091157216926473999609111614204306845838307854234554248792507666256553013,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_dob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 16185177732310477260084943906004223399597368428652335410368759234313937346479,
            leaf_index: 93240,
            sibling_path: [
                16185314510148275117643302100301636302726000384712949917645679395971297426357,
                15969998096259486727970746221106503882396634353779663360738924066890694913169,
                11082766424664628222077369758955803164210892199296911163471836585883269278598,
                17813109994472311877878001470304610044203842282015199989486594609335429166695,
                8189278274265321647855212227449665005655229446870508009011419190716742971487,
                10695922875605352839296242541270468896914490330728845346733325421231938823893,
                21476601499889979239297967897025575904960129232440592658050058866618993874853,
                20850677374571240808668428865667761451139579375210141128662251354608928286415,
                15758314119828963276221533040524747634978967404159609178082772017401247237335,
                492134440768523552086805495365765752251493768760477397892267641999281030241,
                3310216972027424045264550314811017154471924981957590975920096337464017806007,
                8201380046158679181142528890428883815694517254647007857539928068666171835442,
                6802730886220718584050820898159981360409386482502636663713764257068465276373,
                12578059855022539543676144144949594399778565933677368980790781104862780628541,
                12469661751121015863831637497066272123987407425322165788816166548395052973197,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 16185314510148275117643302100301636302726000384712949917645679395971297426357,
            leaf_index: 93241,
            sibling_path: [
                16185177732310477260084943906004223399597368428652335410368759234313937346479,
                15969998096259486727970746221106503882396634353779663360738924066890694913169,
                11082766424664628222077369758955803164210892199296911163471836585883269278598,
                17813109994472311877878001470304610044203842282015199989486594609335429166695,
                8189278274265321647855212227449665005655229446870508009011419190716742971487,
                10695922875605352839296242541270468896914490330728845346733325421231938823893,
                21476601499889979239297967897025575904960129232440592658050058866618993874853,
                20850677374571240808668428865667761451139579375210141128662251354608928286415,
                15758314119828963276221533040524747634978967404159609178082772017401247237335,
                492134440768523552086805495365765752251493768760477397892267641999281030241,
                3310216972027424045264550314811017154471924981957590975920096337464017806007,
                8201380046158679181142528890428883815694517254647007857539928068666171835442,
                6802730886220718584050820898159981360409386482502636663713764257068465276373,
                12578059855022539543676144144949594399778565933677368980790781104862780628541,
                12469661751121015863831637497066272123987407425322165788816166548395052973197,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_yob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 19730106270788425280092367798910448773697094309496274578808059063804713053408,
            leaf_index: 113756,
            sibling_path: [
                19730380503364122347072871235115769778645552502534070561422172454478574407904,
                10820564360728112435516315028388403786916144896537596478263469146568069065890,
                13967628781229888702334061924794759393232473067507231820119873388002867432937,
                11547171983170274498777018637184057325662393918693574560759730497710975136529,
                16981371809573727238307430602854183599938297336501954627775747157890021320459,
                16685493615193667553012921565332038066720258416954039429462223868809017172045,
                2608768326829173795859343391676725055915654722344035005337258160003148399344,
                3204409644017900071112307137107500860755957692935695139399148701113458728353,
                16791724150889627770744319878671770185620617686937984461965559992369089854269,
                16531195885979233337336706973613610563803902193215234473773779581528304932812,
                4681982554062442746268371612927751780207570240998728398547487276477692770196,
                11944073018674702918759392567768428248850499300987010083174595307233334497651,
                14174827611458534542691470947826270202221928681021284183242407217562967377988,
                12746091157216926473999609111614204306845838307854234554248792507666256553013,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 19730380503364122347072871235115769778645552502534070561422172454478574407904,
            leaf_index: 113757,
            sibling_path: [
                19730106270788425280092367798910448773697094309496274578808059063804713053408,
                10820564360728112435516315028388403786916144896537596478263469146568069065890,
                13967628781229888702334061924794759393232473067507231820119873388002867432937,
                11547171983170274498777018637184057325662393918693574560759730497710975136529,
                16981371809573727238307430602854183599938297336501954627775747157890021320459,
                16685493615193667553012921565332038066720258416954039429462223868809017172045,
                2608768326829173795859343391676725055915654722344035005337258160003148399344,
                3204409644017900071112307137107500860755957692935695139399148701113458728353,
                16791724150889627770744319878671770185620617686937984461965559992369089854269,
                16531195885979233337336706973613610563803902193215234473773779581528304932812,
                4681982554062442746268371612927751780207570240998728398547487276477692770196,
                11944073018674702918759392567768428248850499300987010083174595307233334497651,
                14174827611458534542691470947826270202221928681021284183242407217562967377988,
                12746091157216926473999609111614204306845838307854234554248792507666256553013,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
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
            leaf_index: 97036,
            sibling_path: [
                16847877387895272008133175339196796799982204440531370830285746768266245745917,
                16618282185040247415947022839351445875608127695101791937412231647277759093413,
                13134737588014743048117037437507781324922144964950305688310761913812894737278,
                15431525006228354742863033709759268287368900289837288397706614835399880640428,
                14494020608426432366225231964619224287171986986765821693973649518611513885296,
                20226918045167282623305622374527077940878950444464650793565315922652057299300,
                7733530632831393633576692684662051458485935515272941047096321814743980798563,
                19733983984591930951124543851935199263244893398124970924353438194876125061989,
                343439295147048624571381236228577761284060343992371008136009534121663298409,
                12281085839303722021391084884555770651107536142276379317408317160908681574200,
                16122779828210323967122285087375096383442950138877373425068024996443937147795,
                5774410796140190135462277518343034178690121422202964400039621535887499635983,
                11532682995332464721591054321168760736456370291062589726969412117274351427554,
                12578059855022539543676144144949594399778565933677368980790781104862780628541,
                12469661751121015863831637497066272123987407425322165788816166548395052973197,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 16847877387895272008133175339196796799982204440531370830285746768266245745917,
            leaf_index: 97037,
            sibling_path: [
                16847615597941925683125829487704639912742480801748637799512831103621180199493,
                16618282185040247415947022839351445875608127695101791937412231647277759093413,
                13134737588014743048117037437507781324922144964950305688310761913812894737278,
                15431525006228354742863033709759268287368900289837288397706614835399880640428,
                14494020608426432366225231964619224287171986986765821693973649518611513885296,
                20226918045167282623305622374527077940878950444464650793565315922652057299300,
                7733530632831393633576692684662051458485935515272941047096321814743980798563,
                19733983984591930951124543851935199263244893398124970924353438194876125061989,
                343439295147048624571381236228577761284060343992371008136009534121663298409,
                12281085839303722021391084884555770651107536142276379317408317160908681574200,
                16122779828210323967122285087375096383442950138877373425068024996443937147795,
                5774410796140190135462277518343034178690121422202964400039621535887499635983,
                11532682995332464721591054321168760736456370291062589726969412117274351427554,
                12578059855022539543676144144949594399778565933677368980790781104862780628541,
                12469661751121015863831637497066272123987407425322165788816166548395052973197,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    // All 3 proofs
    // Passport
    let passport_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 17678843201822127079666876969156086167683830761763581451616589513039830354873,
            leaf_index: 101887,
            sibling_path: [
                17678483488934989303041571921721254879047474800165078075593658906956492165875,
                6610364792281795014260198959345927065458104257038120310051615204099271167669,
                20143446098143373351115574789874463724657094905390422314561874459636175677217,
                19893691468203207856343450116772538422842222662683739252330869282968010313918,
                18375017133380115549264244094205886217930886888269905022300789542812260107163,
                14450361122162379605006628448487580172133080646512361981558726476851391828522,
                1036862762253276180804636314179061183024782892973299935324260643003293154167,
                8257529312784508492912180973014415084531719922924059455167680904342512386093,
                6060888110532640004278203381347877480103641295060762402570072095219522597696,
                14977465414962876498532718619232933760438657995631681123166861880137327543693,
                2007316816053259234948953164938387248614178337976946887891986282783973292522,
                9189238498999806644198756783538198389204583916899919152742951447721678962963,
                5874980421161757665977513338727910123138275087088599522758714702956879017210,
                10459664789519617235643284513680283692887508692353139451402381241604377011216,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 17679946430902534397335637626482439472280994668445251224471281429426312031564,
            leaf_index: 101888,
            sibling_path: [
                17680009225312899004641896252463515877936801739306389953968307970786015936461,
                15920555220840417433453084217433280607300456601644597478837091775042294952230,
                7077806398237497047822025689811545853856040346317451821759202659869473269398,
                16298277226147465055309164273760489230052064929859787343893458467267129893719,
                13757410589765261182276025064763576951147744505367178873000858015249421979739,
                2997983014641542063604707706941967394204727211279535759797619154898952586828,
                20849608473764511002794092391268919552069638254308513771443657052965792140954,
                6691856577513322747897518495383380663162949013281370171436464449903680140968,
                2546673929177403889858815659399078806388340658165031275163195461683629033646,
                2357390502483756418241243860731164439513252715720685645950608157983412474680,
                2007316816053259234948953164938387248614178337976946887891986282783973292522,
                9189238498999806644198756783538198389204583916899919152742951447721678962963,
                5874980421161757665977513338727910123138275087088599522758714702956879017210,
                10459664789519617235643284513680283692887508692353139451402381241604377011216,
                1704214830929787379728169738650302688713097533582311475513308253832292328493,
                15441374477832832067403020987115514648981625650532786114323990206732691056514,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_dob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 5241331124273529703806704617272911046448928534660311876970425657428036441867,
            leaf_index: 30022,
            sibling_path: [
                5241706441765909250871422924725078949625321825638467420885267645523233061819,
                21703072265898492117469380520861137676437526915431557094944601463982190210595,
                1615981054663722417318831796402477393211529854246022521283598896508385728508,
                13451001766593624105437613876595293418940850663282422368292272266755536976808,
                14646138640567109359841889270014931689085964393097814591892759723536559689046,
                20860667734631241843693703198107816485628919570815562980836677613029357992257,
                8502217453064035879400129324749471895046477885049384861525264171089230638013,
                6687921882316242026992793793550978841138455107582706619426901651306714492770,
                81549277227934170603609187009044262745979635016424642255657490228256979098,
                1001760550780152654018709844046787139255765489188778507878360442735487924042,
                1096776750586595438538549261263405801688412369215258789031509036603118680383,
                20380315093746526882160720766334768926009272345077268575350833212971247812001,
                162641664958058225784881978434194853896065925593795623997871531874239119972,
                17599418490215381828774587320556712726160757374017226077119475062219668243411,
                17370610256219177579402088811071881840699491241308318301512787431106789397928,
                6170047750834888331597810312282160751025283295819884664149158819731763951095,
                18603683295116425944172923198605921892107095987681914655028475372448354804282,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 5241706441765909250871422924725078949625321825638467420885267645523233061819,
            leaf_index: 30023,
            sibling_path: [
                5241331124273529703806704617272911046448928534660311876970425657428036441867,
                21703072265898492117469380520861137676437526915431557094944601463982190210595,
                1615981054663722417318831796402477393211529854246022521283598896508385728508,
                13451001766593624105437613876595293418940850663282422368292272266755536976808,
                14646138640567109359841889270014931689085964393097814591892759723536559689046,
                20860667734631241843693703198107816485628919570815562980836677613029357992257,
                8502217453064035879400129324749471895046477885049384861525264171089230638013,
                6687921882316242026992793793550978841138455107582706619426901651306714492770,
                81549277227934170603609187009044262745979635016424642255657490228256979098,
                1001760550780152654018709844046787139255765489188778507878360442735487924042,
                1096776750586595438538549261263405801688412369215258789031509036603118680383,
                20380315093746526882160720766334768926009272345077268575350833212971247812001,
                162641664958058225784881978434194853896065925593795623997871531874239119972,
                17599418490215381828774587320556712726160757374017226077119475062219668243411,
                17370610256219177579402088811071881840699491241308318301512787431106789397928,
                6170047750834888331597810312282160751025283295819884664149158819731763951095,
                18603683295116425944172923198605921892107095987681914655028475372448354804282,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
    };

    let name_and_yob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 13520906526882975260047628088903941351233487524184204507586188205041172984379,
            leaf_index: 77929,
            sibling_path: [
                13520724679456254784797560335269264600349770909588346167124667588496439306404,
                797718405799143353850077259922215611592288022962023761693310138289546352252,
                7014114072367329884087267983560718873141824578189653859057566900071812422250,
                10045597890471946567457726460739517439922474484649978094844210048788973460019,
                1381238115210696932314335217924168486384568425585578109272655175698964504795,
                14817463039994833107692223323695608413038907052106207973709246514443918906766,
                19009430651782458899887242673079067250766844041748392897841401884276254912343,
                2184024946170549546088194096953951025240427459650062902582423845114902649619,
                15874078144158276250039638045306195339878488707346910855712425685695180131258,
                11945286372771301251153837240833928239338863336751064802422650036510352267776,
                17235652198432593515744083344410673579069928020177231615232806655514171151781,
                17485020898595449334576719123674746575072250626826463936358263448294299212713,
                4420389821990951392372110243452183070248785256373173857751894534076629590659,
                5620049624712083760202601549929403514961750617096897435736573609815674781178,
                2438829298785015674245947852972803351298670490567346671260592308558608267675,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
                3218243980816964110015535469652973420290887819006413761652914020854170460131,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 13521425026896420022203876767580951416401644784854387377332576981467843596093,
            leaf_index: 77930,
            sibling_path: [
                13521502695515903361244935247129799526672778354847082897029932877696748329337,
                14780672967728621196180874399857932566978644150475049623573026605969123931805,
                7014114072367329884087267983560718873141824578189653859057566900071812422250,
                10045597890471946567457726460739517439922474484649978094844210048788973460019,
                1381238115210696932314335217924168486384568425585578109272655175698964504795,
                14817463039994833107692223323695608413038907052106207973709246514443918906766,
                19009430651782458899887242673079067250766844041748392897841401884276254912343,
                2184024946170549546088194096953951025240427459650062902582423845114902649619,
                15874078144158276250039638045306195339878488707346910855712425685695180131258,
                11945286372771301251153837240833928239338863336751064802422650036510352267776,
                17235652198432593515744083344410673579069928020177231615232806655514171151781,
                17485020898595449334576719123674746575072250626826463936358263448294299212713,
                4420389821990951392372110243452183070248785256373173857751894534076629590659,
                5620049624712083760202601549929403514961750617096897435736573609815674781178,
                2438829298785015674245947852972803351298670490567346671260592308558608267675,
                19463981340307350320021110048161204669953124625441990552839847617090045440793,
                48965690409285468029915012961748482331618424664620953811067367018650070817,
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
        leaf_index: 57070,
        sibling_path: [
            9917525085591752581815867813532608282359240187823645181665529410618628728607,
            11024720902279861419707121301282248041705611189334295156511954285840747507681,
            6093210581771637141817501526156021647071588678207749129795154601225450335984,
            21557156977843397563230019795454032336154610869060080115810964630067739381775,
            525152197508306438415845891017264353252280392817907875036646549756386798490,
            17027532763028032045609667908146807398933878510250484298013381664050338886380,
            4258851587840297575757919362131042591997712692864410864843044615548236976087,
            20058026658998762090878767264285225929110573584189252232088241492168476779018,
            12007708726336644823628535739563288646877732292094648407738365038341516155609,
            12334012466530044503708088029127195535605883656264922297607521473999562737133,
            19582666126365533658143192136117783018968407759197979471139451711186714817796,
            14058483685472431627034796845617326784026902534036835598958196290194680760975,
            1913885167271226048900869664928774533906534828591045315003513706548389395567,
            10137962158573734050162686176154332483946400485913588436121049706320967897922,
            20865758332970325045263219825193635787614754990818729783792516628094684528923,
            21492147508593555798954276854884538585208918386284299128827770232157281300008,
            18603683295116425944172923198605921892107095987681914655028475372448354804282,
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
        leaf_index: 57070,
        sibling_path: [
            9917525085591752581815867813532608282359240187823645181665529410618628728607,
            11024720902279861419707121301282248041705611189334295156511954285840747507681,
            6093210581771637141817501526156021647071588678207749129795154601225450335984,
            21557156977843397563230019795454032336154610869060080115810964630067739381775,
            525152197508306438415845891017264353252280392817907875036646549756386798490,
            17027532763028032045609667908146807398933878510250484298013381664050338886380,
            4258851587840297575757919362131042591997712692864410864843044615548236976087,
            20058026658998762090878767264285225929110573584189252232088241492168476779018,
            12007708726336644823628535739563288646877732292094648407738365038341516155609,
            12334012466530044503708088029127195535605883656264922297607521473999562737133,
            19582666126365533658143192136117783018968407759197979471139451711186714817796,
            14058483685472431627034796845617326784026902534036835598958196290194680760975,
            1913885167271226048900869664928774533906534828591045315003513706548389395567,
            10137962158573734050162686176154332483946400485913588436121049706320967897922,
            20865758332970325045263219825193635787614754990818729783792516628094684528923,
            21492147508593555798954276854884538585208918386284299128827770232157281300008,
            18603683295116425944172923198605921892107095987681914655028475372448354804282,
            3218243980816964110015535469652973420290887819006413761652914020854170460131,
        ],
    };

    ordered_mt_verify_inclusion(trees.root(), name_inclusion_proof);
}
