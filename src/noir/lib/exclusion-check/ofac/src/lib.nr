pub mod smt;

use crate::smt::smt_verify;
use std::hash::poseidon2::Poseidon2;

use utils::{
    get_dob_from_mrz, get_document_number_from_mrz, get_name_from_mrz, get_nationality_from_mrz,
    get_yob_from_mrz, MRZDOB, MRZDocumentNumber, MRZName, MRZNationality, MRZYOB,
    PASSPORT_MRZ_BIRTHDATE_INDEX, PASSPORT_MRZ_COUNTRY_INDEX, PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
    PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NATIONALITY_INDEX,
};

type OFACSparseMerkleTreeProof = [Field; 254];

global PASSPORT_NO_AND_NATIONALITY_SMT_ROOT: Field =
    16848446384455121992563997739935529719802501789913623635566264898903689098267;
global NAME_AND_DOB_SMT_ROOT: Field =
    18507461810352107710831511830002125926438894298854758698832085735090034844439;
global NAME_AND_YOB_SMT_ROOT: Field =
    21214931644386285663256497249965874333059934725605058568752759284223990155398;

// TOOD: combine into one tree and perform all checks in one go
// TODO: include series of fuzzy matches for the names into the merkle tree?
pub struct OFACSparseMerkleTrees {
    pub passportNoAndNationalitySMTRoot: Field,
    pub nameAndDobSMTRoot: Field,
    pub nameAndYobSMTRoot: Field,
}

impl OFACSparseMerkleTrees {
    /**
     * Note: default currently using the values created in our testing implementation
     */
    pub fn default() -> Self {
        Self {
            passportNoAndNationalitySMTRoot: PASSPORT_NO_AND_NATIONALITY_SMT_ROOT,
            nameAndDobSMTRoot: NAME_AND_DOB_SMT_ROOT,
            nameAndYobSMTRoot: NAME_AND_YOB_SMT_ROOT,
        }
    }
}

pub struct OFACMerkleProof {
    pub leaf_value: Field,
    pub siblings: OFACSparseMerkleTreeProof,
}

impl OFACMerkleProof {
    pub fn new(leaf_value: Field, siblings: OFACSparseMerkleTreeProof) -> Self {
        Self { leaf_value, siblings }
    }
}

pub struct OFACSparseMerkleTreeProofs {
    pub passportNoAndNationalitySMTProof: OFACMerkleProof,
    pub nameAndDobSMTProof: OFACMerkleProof,
    pub nameAndYobSMTProof: OFACMerkleProof,
}

impl OFACSparseMerkleTreeProofs {
    pub fn new(
        passportNoAndNationalitySMTProof: OFACMerkleProof,
        nameAndDobSMTProof: OFACMerkleProof,
        nameAndYobSMTProof: OFACMerkleProof,
    ) -> Self {
        Self { passportNoAndNationalitySMTProof, nameAndDobSMTProof, nameAndYobSMTProof }
    }
}

impl OFACSparseMerkleTrees {
    pub fn check_ofac_exclusion(self: Self, dg1: [u8; 95], proofs: OFACSparseMerkleTreeProofs) {
        // Calculate the hashes
        let name: MRZName = get_name_from_mrz(dg1);
        let dob: MRZDOB = get_dob_from_mrz(dg1);
        let yob: MRZYOB = get_yob_from_mrz(dg1);
        let document_number: MRZDocumentNumber = get_document_number_from_mrz(dg1);
        let nationality: MRZNationality = get_nationality_from_mrz(dg1);

        let passportNoAndNationality = array_concat_as_field(document_number, nationality);
        let passportNoAndNationalityHash: Field =
            Poseidon2::hash(passportNoAndNationality, passportNoAndNationality.len());

        let nameAndDob = array_concat_as_field(name, dob);
        let nameAndDobHash: Field = Poseidon2::hash(nameAndDob, nameAndDob.len());

        let nameAndYob = array_concat_as_field(name, yob);
        let nameAndYobHash: Field = Poseidon2::hash(nameAndYob, nameAndYob.len());

        smt_exculsion_check(
            passportNoAndNationalityHash,
            self.passportNoAndNationalitySMTRoot,
            proofs.passportNoAndNationalitySMTProof,
        );
        smt_exculsion_check(
            nameAndDobHash,
            self.nameAndDobSMTRoot,
            proofs.nameAndDobSMTProof,
        );
        smt_exculsion_check(
            nameAndYobHash,
            self.nameAndYobSMTRoot,
            proofs.nameAndYobSMTProof,
        );
    }
}

fn smt_exculsion_check(hash: Field, root: Field, proof: OFACMerkleProof) {
    assert(smt_verify(hash, proof.leaf_value, root, proof.siblings, false));
}

/**
 * Concatenate two arrays (of different sizes) into one array
 */
fn array_concat_as_field<let N: u32, let M: u32>(
    array1: [u8; N],
    array2: [u8; M],
) -> [Field; N + M] {
    let mut result = [0 as Field; N + M];
    for i in 0..N {
        result[i] = array1[i] as Field;
    }
    for i in 0..M {
        result[N + i] = array2[i] as Field;
    }
    result
}

#[test]
fn test_tree_non_inclusion() {
    let trees: OFACSparseMerkleTrees = OFACSparseMerkleTrees::default();

    // 1n does not exist in each of the trees - test this
    let test_non_inclusion_of = 1;

    let passport_matching_entry =
        1093118169427159278724258995644555677240945612393487754418633875877235765249;
    let mut passport_membership_proof: [Field; 254] = [0; 254];

    passport_membership_proof[0] =
        10826523085272747055574429579796927765610612992065373924379136503389258207301;
    passport_membership_proof[1] =
        8111879015395595795459743758393377742009960661743559101634355702216980008428;
    passport_membership_proof[2] =
        10614482260704129943493125370369954755086323558791096102535310577492884480781;
    passport_membership_proof[3] =
        12339765051870052145408276754332404782500976217913011949803842544502056105756;
    passport_membership_proof[4] =
        2104855441846581553436767421905386573080499736408142365950956216747257391790;
    passport_membership_proof[5] =
        16430154115512523849673936126446325887211907514744571053181860231208525300909;
    passport_membership_proof[6] =
        18506549271340416602059437408311269818924070621671186125925300499466214264214;
    passport_membership_proof[7] =
        6840826508796401795807600855116316799776359045308030764893303484301105573000;
    passport_membership_proof[8] =
        2701078743466579347190837269865238938501979336192575655122191724202357317760;
    passport_membership_proof[9] =
        6581477954448348199988676986168378620376703588290737558733019388788884762669;
    passport_membership_proof[10] =
        4738882917628176677488969682241605833750863904591392646515870734335960594807;

    let proof = OFACMerkleProof::new(passport_matching_entry, passport_membership_proof);

    smt_exculsion_check(
        test_non_inclusion_of,
        trees.passportNoAndNationalitySMTRoot,
        proof,
    );
}

struct DG1Builder {
    dg1: [u8; 95],
}

impl DG1Builder {
    pub fn new(dg1: [u8; 95]) -> Self {
        Self { dg1 }
    }

    pub fn build(mut self: Self) -> [u8; 95] {
        self.dg1
    }

    pub fn with_country_code(mut self: Self, country_code: [u8; 3]) -> Self {
        for i in 0..3 {
            // - 5 as it goes through an mrz decoding
            self.dg1[PASSPORT_MRZ_NATIONALITY_INDEX + i + 5] = country_code[i];
            self.dg1[PASSPORT_MRZ_COUNTRY_INDEX + i + 5] = country_code[i];
        }
        self
    }

    pub fn with_document_number(mut self: Self, document_number: [u8; 9]) -> Self {
        for i in 0..9 {
            self.dg1[PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + i + 5] = document_number[i];
        }
        self
    }

    pub fn with_name(mut self: Self, name: [u8; 39]) -> Self {
        for i in 0..39 {
            self.dg1[PASSPORT_MRZ_NAME_INDEX + i + 5] = name[i];
        }
        self
    }

    pub fn with_dob(mut self: Self, dob: [u8; 6]) -> Self {
        for i in 0..6 {
            self.dg1[PASSPORT_MRZ_BIRTHDATE_INDEX + i + 5] = dob[i];
        }
        self
    }
}

#[test]
fn non_inclusion_of_empty_dg1() {
    // Provide the non inclusion proofs for an empty dg1
    let dg1 = DG1Builder::new([0; 95]);
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

    let dg1 = dg1
        .with_document_number(passport_no)
        .with_country_code(country)
        .with_name(name)
        .with_dob(dob)
        .build();

    let trees: OFACSparseMerkleTrees = OFACSparseMerkleTrees::default();

    // All 3 proofs
    // Passport
    let mut passportSiblingPath: [Field; 254] = [0; 254];
    passportSiblingPath[0] =
        16096210923039937324900828729111851711879712779488695127870682399802737193884;
    passportSiblingPath[1] =
        1259339816235086749162321606998607328270810645289774617790454435606519121609;
    passportSiblingPath[2] =
        20543319044030453302476369002660387159601890495716961410458808306453221174974;
    passportSiblingPath[3] =
        19253058202363131577685920340592631531845832080856179246844706882170554085155;
    passportSiblingPath[4] =
        13366896729772485899921831490385010885097602016648681371255200464711118398636;
    passportSiblingPath[5] =
        19002150991825718238981100417252024736937392443375716409684138663038750689406;
    passportSiblingPath[6] =
        17877548090904086505081491729523635117099489473351483530845700699753463321687;
    passportSiblingPath[7] =
        11894041369137053750788213205665888912956212251677794079004819749951263093228;
    passportSiblingPath[8] =
        2981833973015443397516778913472478290466683862835478180425902574882337706831;
    passportSiblingPath[9] =
        10508342124554657494809161963799015397745355177617267590375530235126947287045;

    let passportProof = OFACMerkleProof::new(
        19472559416252533469288112994110593837599677348457724900723337162843562794498,
        passportSiblingPath,
    );

    // Name and DOB

    let mut name_and_dob_sibling_path: [Field; 254] = [0; 254];
    name_and_dob_sibling_path[0] =
        7141086647127818325201212518361484824181088650468941216777477874624255894769;
    name_and_dob_sibling_path[1] =
        7944976814530298889505930011536118403304045049218751037086280821105331773371;
    name_and_dob_sibling_path[2] =
        11809190433016891642298368180753859143149662240597491292070810089105115849730;
    name_and_dob_sibling_path[3] =
        930608147923981282423434818279715196040189163955993620767566328757709809743;
    name_and_dob_sibling_path[4] =
        20534596668939841228626293325435879514494161911839908602179799973849831464782;
    name_and_dob_sibling_path[5] =
        4665537423158182840960684031921877067649197067833067676233117796594869170609;
    name_and_dob_sibling_path[6] =
        11817005937478756880073505708331136796678417469518699468241016002553196118500;
    name_and_dob_sibling_path[7] =
        1213000111505132626101391210385603872074541873605652842656329687886837163834;
    name_and_dob_sibling_path[8] =
        11306840051542574348870752467372573240016431802192596231928393264709616673289;
    name_and_dob_sibling_path[9] =
        19465899688486083271949721704749513869817593921625890642878077067507654862535;
    name_and_dob_sibling_path[10] =
        1289496103794342786988995225059208340012574053682380550732516312764291255301;
    name_and_dob_sibling_path[11] =
        2031392442953363413049904193869369104983178771948117285085274801813287079146;

    let name_and_dob_proof = OFACMerkleProof::new(
        14305617601987334507121318634003416308804163528067844350398755777270743444453,
        name_and_dob_sibling_path,
    );

    // Name and YOB
    let mut name_and_yob_sibling_path: [Field; 254] = [0; 254];
    name_and_yob_sibling_path[0] =
        12856494218089720218684794994764166524749114511033463633655138251243066361735;
    name_and_yob_sibling_path[1] =
        15672664229208040178285244543500325320216945598379380817684504376224241668065;
    name_and_yob_sibling_path[2] =
        14034221388689637253693633564631710008456741128436186333639371499320785660224;
    name_and_yob_sibling_path[3] =
        16952744162231366199328807590001619325628160487430638335636280438525482363112;
    name_and_yob_sibling_path[4] =
        12056013812435680286295675998738897047126511820020198710146667701142368435671;
    name_and_yob_sibling_path[5] =
        13816779950457214554760376931493048206239974135260050480835737153477569893597;
    name_and_yob_sibling_path[6] =
        2909609121277937445046916338825733619244295317876733195791317580776211920978;
    name_and_yob_sibling_path[7] =
        13178542581014549657444817164561242949247628439400848023306629240230513349451;
    name_and_yob_sibling_path[8] =
        19535554696520081232986225237733083991074116849399898989137654718380869211750;
    name_and_yob_sibling_path[9] =
        2297572651571629939287804069685448939123531911923967521959304331143466879588;
    name_and_yob_sibling_path[10] =
        6146618489896349227300065796897529560772263080863723433414648464969176625605;
    name_and_yob_sibling_path[11] =
        12148751839853604497868754351670223320917868688906439874619148651659155988294;

    let name_and_yob_proof = OFACMerkleProof::new(
        14994561155353715731291174895414924107805673982226109022704420914564565471404,
        name_and_yob_sibling_path,
    );

    let smt_proofs =
        OFACSparseMerkleTreeProofs::new(passportProof, name_and_dob_proof, name_and_yob_proof);

    trees.check_ofac_exclusion(dg1, smt_proofs);
}
