pub mod ordered_mt;
pub mod types;
pub mod param_commit;

use crate::ordered_mt::ordered_mt_non_membership;
use poseidon::poseidon2::Poseidon2;
use utils::tests::DG1Builder;

use types::{
    SanctionsOrderedMerkleTreeInclusionProof, SanctionsOrderedMerkleTreeProof,
    SanctionsOrderedMerkleTreeProofs,
};

use utils::{
    array_concat_as_field,
    get_dob_from_mrz,
    get_document_number_from_mrz,
    get_name_from_mrz,
    get_nationality_from_mrz,
    get_yob_from_mrz,
    types::{DG1Data, MRZDOB, MRZDocumentNumber, MRZName, MRZNationality, MRZYOB},
    find_subarray_index,
    u8_array_to_fields,
    find_subarray_index_after_index,
    constants::{ASCII_CODE_FOR_LESS_THAN, PASSPORT_MRZ_NAME_LENGTH}
};

global TREE_ROOT: Field = 0x099699583ea7729a4a05821667645e927b74feb4e6e5382c6e4370e35ed2b23c;

/// Get the 3 possible last name + first name combinations from the MRZ.
///
/// This is necessary as the actual first name could be splitted into multiple parts
/// by the < characters, e.g. Jean-Pierre -> JEAN<PIERRE<<<<...
///
/// # Arguments
///
/// * `dg1` - The DG1 of the passport or ID card
///
/// # Returns
///
/// A tuple of the 3 possibles last name + first name combinations
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
    assert_eq(full_name[last_name_end_index], ASCII_CODE_FOR_LESS_THAN, "Invalid index for last name end");
    assert_eq(full_name[last_name_end_index + 1], ASCII_CODE_FOR_LESS_THAN, "Invalid index for last name end");
    // Gets the index of where the first given name starts (i.e. after the <<)
    let first_name_start_index = last_name_end_index + full_name_separator.len();
    // The first given name must be present, an ID will have at least one given name
    assert(full_name[first_name_start_index] != ASCII_CODE_FOR_LESS_THAN, "Invalid index for first name start");

    // Gets the index of where the second given name (or the second part of the first name) starts
    let second_name_start_index = find_subarray_index_after_index(single_name_separator, full_name, first_name_start_index) + 1;
    // Note: we don't check if the character after is not < as there might not be a second given name (e.g. John Doe -> DOE<<JOHN<<<<....)
    assert(second_name_start_index > first_name_start_index, "Second name start index must be after first name start index");
    // Checking the separator is there at the expected index
    assert_eq(full_name[second_name_start_index - 1], ASCII_CODE_FOR_LESS_THAN, "Invalid index for second name start");
    // If we get a < here, then all the following characters must be <
    if (full_name[second_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            if i > second_name_start_index {
                assert_eq(full_name[i], ASCII_CODE_FOR_LESS_THAN, "Invalid index for second name start");
            }
        }
    }

    // Gets the index of where the third given name (or the third part of the first name) starts
    let third_name_start_index = find_subarray_index_after_index(single_name_separator, full_name, second_name_start_index) + 1;
    // Note: we don't check if the character after is not < as there might not be a third given name (e.g. John Miller Doe -> DOE<<JOHN<MILLER<<<....)
    assert(third_name_start_index > second_name_start_index, "Third name start index must be after second name start index");
    // Checking the separator is there at the expected index
    assert_eq(full_name[third_name_start_index - 1], ASCII_CODE_FOR_LESS_THAN, "Invalid index for third name start");
    // If we get a < here, then all the following characters must be <
    if (full_name[third_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            if i > third_name_start_index {
                assert_eq(full_name[i], ASCII_CODE_FOR_LESS_THAN, "Invalid index for second name start");
            }
        }
    }

    // Gets the index of where the fourth given name (or the fourth part of the first name) starts
    let fourth_name_start_index = find_subarray_index_after_index(single_name_separator, full_name, third_name_start_index) + 1;
    // Note: we don't check if the character after is not < as there might not be a fourth given name (e.g. John Miller Doe -> DOE<<JOHN<MILLER<<<....)
    assert(fourth_name_start_index > third_name_start_index, "Fourth name start index must be after third name start index");
    // Checking the separator is there at the expected index
    assert_eq(full_name[fourth_name_start_index - 1], ASCII_CODE_FOR_LESS_THAN, "Invalid index for fourth name start");
    // If we get a < here, then all the following characters must be <
    if (full_name[fourth_name_start_index] == ASCII_CODE_FOR_LESS_THAN) {
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            if i > fourth_name_start_index {
                assert_eq(full_name[i], ASCII_CODE_FOR_LESS_THAN, "Invalid index for second name start");
            }
        }
    }


    // Last name + whatever comes before the first < (could be a whole first name or a partial first name, 
    // e.g. Jean-Pierre Dupont -> DUPONT<<JEAN<PIERRE<<<<..., only DUPONT<<JEAN<<<... would be considered here)
    let name_1 =  if second_name_start_index < PASSPORT_MRZ_NAME_LENGTH { 
        // Implicitly fills the rest with <
        let mut result = [ASCII_CODE_FOR_LESS_THAN; PASSPORT_MRZ_NAME_LENGTH];
        for i in 0..PASSPORT_MRZ_NAME_LENGTH {
            // Push characters from the original MRZ name up until the second <
            if i < second_name_start_index {
                result[i] = full_name[i];
            }
        }
        result
    } else { std::mem::zeroed() };
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
    } else { std::mem::zeroed() };
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
    } else { std::mem::zeroed() };
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
        Self { tree: TREE_ROOT }
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

        let name_hash_1: Field = Poseidon2::hash(u8_array_to_fields(name_1), PASSPORT_MRZ_NAME_LENGTH);
        let name_hash_2: Field = Poseidon2::hash(u8_array_to_fields(name_2), PASSPORT_MRZ_NAME_LENGTH);
        let name_hash_3: Field = Poseidon2::hash(u8_array_to_fields(name_3), PASSPORT_MRZ_NAME_LENGTH);

        let passport_no_and_nationality = array_concat_as_field(document_number, nationality);
        let passport_no_and_nationality_hash_1: Field =
            Poseidon2::hash(passport_no_and_nationality, passport_no_and_nationality.len());

        let (name_and_dob_1, name_and_dob_2, name_and_dob_3) = (array_concat_as_field(name_1, dob), array_concat_as_field(name_2, dob), array_concat_as_field(name_3, dob));
        let name_and_dob_hash_1: Field = Poseidon2::hash(name_and_dob_1, name_and_dob_1.len());
        let name_and_dob_hash_2: Field = Poseidon2::hash(name_and_dob_2, name_and_dob_2.len());
        let name_and_dob_hash_3: Field = Poseidon2::hash(name_and_dob_3, name_and_dob_3.len());

        let (name_and_yob_1, name_and_yob_2, name_and_yob_3) = (array_concat_as_field(name_1, yob), array_concat_as_field(name_2, yob), array_concat_as_field(name_3, yob));
        let name_and_yob_hash_1: Field = Poseidon2::hash(name_and_yob_1, name_and_yob_1.len());
        let name_and_yob_hash_2: Field = Poseidon2::hash(name_and_yob_2, name_and_yob_2.len());
        let name_and_yob_hash_3: Field = Poseidon2::hash(name_and_yob_3, name_and_yob_3.len());

        // If the strict mode is enabled, we need to check against just the names
        // which has a higher likelihood of matching against an entry of the sanctions
        // hence why it should be explicitly enabled by the prover
        if (is_strict) {
            // Check against the names
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
fn non_inclusion_of_dg1() {
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

    // All 3 proofs
    // Passport
    let passport_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18674386456615172342841733396108603959611017967778897078549388798634214809915,
            leaf_index: 12932,
            sibling_path: [
                18685769843055597499770478244511153080171577100184040638075341991887898947043,
                18062426656162546701301295540229307599823193544964404269704722798035772794829,
                17080956354011133277740417906793460016601348975426035946703986039569454778795,
                8372446026571647841991115383146414615145781805068008227048407759105489506457,
                19943474646442620277864338385265689608746162382874961317974928870759831551741,
                19117508257520153817844273951587666648213989273839307574304384352723927920386,
                16722852517660319940011305887926857456729951473445856705316309622229743250484,
                2084980793718652547410683490633300704775368873840176663196341996702695911923,
                2048903433457172877133384876663102095462716928723337386481310504236642232099,
                644981785317420079670219972303905959614466993555536695148740116431534958284,
                7256028571690491881642631178782579640988781456421869946053525734637979534286,
                2611349503535189477813706760100792035080150380127488673817844562830098205773,
                15236479295721617014743664357334345673933025126262198527474928621116479703894,
                12805425192976271374398140166310628666364347092844927278695128369445091963047,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 18685769843055597499770478244511153080171577100184040638075341991887898947043,
            leaf_index: 12933,
            sibling_path: [
                18674386456615172342841733396108603959611017967778897078549388798634214809915,
                18062426656162546701301295540229307599823193544964404269704722798035772794829,
                17080956354011133277740417906793460016601348975426035946703986039569454778795,
                8372446026571647841991115383146414615145781805068008227048407759105489506457,
                19943474646442620277864338385265689608746162382874961317974928870759831551741,
                19117508257520153817844273951587666648213989273839307574304384352723927920386,
                16722852517660319940011305887926857456729951473445856705316309622229743250484,
                2084980793718652547410683490633300704775368873840176663196341996702695911923,
                2048903433457172877133384876663102095462716928723337386481310504236642232099,
                644981785317420079670219972303905959614466993555536695148740116431534958284,
                7256028571690491881642631178782579640988781456421869946053525734637979534286,
                2611349503535189477813706760100792035080150380127488673817844562830098205773,
                15236479295721617014743664357334345673933025126262198527474928621116479703894,
                12805425192976271374398140166310628666364347092844927278695128369445091963047,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
    };

    let name_and_dob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 10982589642709534277986213660166790642591757156405314643744842156507813418736,
            leaf_index: 7585,
            sibling_path: [
                10981939444348637427474753295439012938004924082786255413805487861467900330258,
                20140406180530062383200458270261806173284532514925415117298176827690365847583,
                3628035101821461462204902955611415473655014558706518485382969987756646869200,
                12272125157205801602851361067984152510161390425157040825800292578831352556448,
                8793089592779706067765001751181857090464748422676066424475454969300302569062,
                20101655812991192151659614749182454042607561059218101700696461733270504594439,
                8175465800073335685470547188847606370369001584843292303924325958449504723355,
                16316729765069656150154966079495703332940315985413232568489080259810316441916,
                8775935778371123020945262930105399353178796896472876390250666298642113932935,
                906831598784779884899396799853388453174996741737662984713027915468873022482,
                7293484108062652852278340377741840128109578496640706355677498810074062062950,
                3334274773393436885808153151314579960273373204456072276141914895359076019483,
                16732917325098723254475925006333356967553230951964204079242396290873849415587,
                16684379666575197569975881162094932530011128293669323252661093859354006127720,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 10985957995973822016942471676233551053569376599430788654641801233665729007498,
            leaf_index: 7586,
            sibling_path: [
                10988316749241412875786884317369210288108650195117535820460740399526918901296,
                14265941937822268484834516108357544567120600583541089085473848692736926937953,
                3628035101821461462204902955611415473655014558706518485382969987756646869200,
                12272125157205801602851361067984152510161390425157040825800292578831352556448,
                8793089592779706067765001751181857090464748422676066424475454969300302569062,
                20101655812991192151659614749182454042607561059218101700696461733270504594439,
                8175465800073335685470547188847606370369001584843292303924325958449504723355,
                16316729765069656150154966079495703332940315985413232568489080259810316441916,
                8775935778371123020945262930105399353178796896472876390250666298642113932935,
                906831598784779884899396799853388453174996741737662984713027915468873022482,
                7293484108062652852278340377741840128109578496640706355677498810074062062950,
                3334274773393436885808153151314579960273373204456072276141914895359076019483,
                16732917325098723254475925006333356967553230951964204079242396290873849415587,
                16684379666575197569975881162094932530011128293669323252661093859354006127720,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
    };

    let name_and_yob_proof = SanctionsOrderedMerkleTreeProof {
        left: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 21802775494169570712054597594722503615270255853359869283706744891343336934794,
            leaf_index: 15068,
            sibling_path: [
                21804392937202599856385198671766495001600615926403073435226201602406279356638,
                20810504887625720469280349887870957848496804608159123082623973344945558080479,
                18624560640133844045926972729740960728378296182876906259641628383295564281856,
                8841763400396559760332806143535393957659641445476523510887926804363033768348,
                9400527909875384245649312518726411393159900420635966686143085649507462721597,
                7615313573656146715466704971055205655475263931096261716418726866745852320036,
                12544473381119097222568816219803294658460326958602700390460883385971752532219,
                127521354151127114969829080163620051849382381421009214883693851097619454876,
                3439951329440540602495506380938148913174102832352702151145808880571407510298,
                14201519506941561169178646204296929171680795708950005800962598406606725168719,
                19208047717975195819992968481289292904158208618635067144381052124352153142918,
                870835666639816584555880757893590158074065675496337234731029459433256674079,
                15236479295721617014743664357334345673933025126262198527474928621116479703894,
                12805425192976271374398140166310628666364347092844927278695128369445091963047,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
        right: SanctionsOrderedMerkleTreeInclusionProof {
            leaf: 21804392937202599856385198671766495001600615926403073435226201602406279356638,
            leaf_index: 15069,
            sibling_path: [
                21802775494169570712054597594722503615270255853359869283706744891343336934794,
                20810504887625720469280349887870957848496804608159123082623973344945558080479,
                18624560640133844045926972729740960728378296182876906259641628383295564281856,
                8841763400396559760332806143535393957659641445476523510887926804363033768348,
                9400527909875384245649312518726411393159900420635966686143085649507462721597,
                7615313573656146715466704971055205655475263931096261716418726866745852320036,
                12544473381119097222568816219803294658460326958602700390460883385971752532219,
                127521354151127114969829080163620051849382381421009214883693851097619454876,
                3439951329440540602495506380938148913174102832352702151145808880571407510298,
                14201519506941561169178646204296929171680795708950005800962598406606725168719,
                19208047717975195819992968481289292904158208618635067144381052124352153142918,
                870835666639816584555880757893590158074065675496337234731029459433256674079,
                15236479295721617014743664357334345673933025126262198527474928621116479703894,
                12805425192976271374398140166310628666364347092844927278695128369445091963047,
                720777601321551456724742356376872832235514487302799006897322578639686749258,
            ],
        },
    };

    let smt_proofs = SanctionsOrderedMerkleTreeProofs {
        passport_no_and_nationality_proof: passport_proof,
        name_and_dob_proof: name_and_dob_proof,
        name_and_yob_proof: name_and_yob_proof,
    };

    trees.check_sanctions_exclusion(dg1, smt_proofs, true);
}
