pub mod ordered_mt;
pub mod types;
pub mod param_commit;
mod tests;

use crate::ordered_mt::{ordered_mt_non_membership, ordered_mt_verify_inclusion};
use poseidon::poseidon2::Poseidon2;

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

/// This function is always used within get_last_name_and_first_name_from_mrz
/// so the rest of the necessary constraints are already done in get_last_name_and_first_name_from_mrz
pub fn process_name(name: MRZName) -> MRZName {
    let mut result = name;
    let full_name_separator = [ASCII_CODE_FOR_LESS_THAN, ASCII_CODE_FOR_LESS_THAN];
    let full_name_separator_index = find_subarray_index(full_name_separator, name);
    // This means the full name separator was not found, this can be the case in some rare cases
    // like with Malaysian passports
    let has_full_name_separator = full_name_separator_index < PASSPORT_MRZ_NAME_LENGTH
        & (name[full_name_separator_index] == ASCII_CODE_FOR_LESS_THAN)
        & (name[full_name_separator_index + 1] == ASCII_CODE_FOR_LESS_THAN)
        // This is to make sure this is not just the right padding of MRZ name
        & (name[full_name_separator_index + 2] != ASCII_CODE_FOR_LESS_THAN);
    if !has_full_name_separator {
        let first_angular_bracket_index = find_subarray_index([ASCII_CODE_FOR_LESS_THAN], name);
        // If the first angular bracket index was found, we process the name to add an angular bracket right after the first one
        // so it meets the standard MRZ name formatting (i.e. LASTNAME<<FIRSTNAME)
        if first_angular_bracket_index < PASSPORT_MRZ_NAME_LENGTH {
            for i in 0..PASSPORT_MRZ_NAME_LENGTH {
                if i < first_angular_bracket_index {
                    result[i] = name[i];
                } else if (i == first_angular_bracket_index)
                    | (i == first_angular_bracket_index + 1) {
                    result[i] = ASCII_CODE_FOR_LESS_THAN;
                } else {
                    // We shift the characters to account for the new angular bracket
                    // even it means potentially dropping the last character of the name
                    // but this is rather unlikely to happen
                    result[i] = name[i - 1];
                }
            }
        }
    }
    result
}

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
    let full_name = process_name(get_name_from_mrz(dg1));
    // << is the separator between the last name and the first name
    // Everything before is the last name, everything after is the first name, middle names, and other given names
    let full_name_separator = [ASCII_CODE_FOR_LESS_THAN, ASCII_CODE_FOR_LESS_THAN];
    // < is the separator between any given name or as a replacement for spaces, hyphens, etc.
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
    // Last name + whatever comes before the third < (this should cover most possible first names with hyphens or other characters replaced by <)
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

    pub fn new(root: Field) -> Self {
        Self { tree: root }
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
            ordered_mt_non_membership(self.tree, name_hash_1, proofs.name_proofs[0]);
            ordered_mt_non_membership(self.tree, name_hash_2, proofs.name_proofs[1]);
            ordered_mt_non_membership(self.tree, name_hash_3, proofs.name_proofs[2]);
        }

        // Check against the passport no and nationality
        ordered_mt_non_membership(
            self.tree,
            passport_no_and_nationality_hash_1,
            proofs.passport_no_and_nationality_proof,
        );
        // Check against the names and DOB
        ordered_mt_non_membership(
            self.tree,
            name_and_dob_hash_1,
            proofs.name_and_dob_proofs[0],
        );
        ordered_mt_non_membership(
            self.tree,
            name_and_dob_hash_2,
            proofs.name_and_dob_proofs[1],
        );
        ordered_mt_non_membership(
            self.tree,
            name_and_dob_hash_3,
            proofs.name_and_dob_proofs[2],
        );
        // Check against the names and YOB
        ordered_mt_non_membership(
            self.tree,
            name_and_yob_hash_1,
            proofs.name_and_yob_proofs[0],
        );
        ordered_mt_non_membership(
            self.tree,
            name_and_yob_hash_2,
            proofs.name_and_yob_proofs[1],
        );
        ordered_mt_non_membership(
            self.tree,
            name_and_yob_hash_3,
            proofs.name_and_yob_proofs[2],
        );
    }
}
