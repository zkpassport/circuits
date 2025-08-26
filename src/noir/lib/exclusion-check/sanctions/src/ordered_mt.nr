// c.t. /self/noir/crates/dg1/src/utils/
use crate::types::{
    SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH, SanctionsOrderedMerkleTreeInclusionProof,
    SanctionsOrderedMerkleTreeProof,
};
use poseidon::poseidon2::Poseidon2;

///
/// Ordered Merkle Tree Inclusion Proof
///
/// Performs a normal merkle tree inclusion proof
///
pub fn ordered_mt_verify_inclusion(
    root: Field,
    inclusion_proof: SanctionsOrderedMerkleTreeInclusionProof,
) {
    let path_in_bits: [u1; SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH] =
        inclusion_proof.leaf_index.to_be_bits::<SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH>();

    let mut current = inclusion_proof.leaf;
    for i in 0..SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH {
        let (left, right) = if path_in_bits[SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH - i - 1] == 1 {
            (inclusion_proof.sibling_path[i], current)
        } else {
            (current, inclusion_proof.sibling_path[i])
        };

        current = Poseidon2::hash([left, right], 2);
    }
    assert(current == root);
}

pub fn ordered_mt_non_membership(root: Field, leaf: Field, proof: SanctionsOrderedMerkleTreeProof) {
    // Perform inclusion checks for bothe the closest upper and the closest lower
    ordered_mt_verify_inclusion(root, proof.left);
    ordered_mt_verify_inclusion(root, proof.right);

    // Check that the closest upper and closest lower are lower / greater than the leaf value
    assert(proof.left.leaf.lt(leaf));
    assert(leaf.lt(proof.right.leaf));

    // Check that their indexes are adjacent
    assert(proof.left.leaf_index + 1 == proof.right.leaf_index);
}

#[test]
fn test_ordered_mt_non_membership() {
    // Run yarn generate-sanction-test-data to generate the test data
    // const passportNoAndCountrySMT = await AsyncOrderedMT.fromSerialized(passportNoAndCountryJson, poseidon2)
    // const passportNoAndCountryNonMembershipProof = await passportNoAndCountrySMT.createNonMembershipProof(1n);
    // console.log(passportNoAndCountryNonMembershipProof);

    let root = 0x099699583ea7729a4a05821667645e927b74feb4e6e5382c6e4370e35ed2b23c;
    let leaf = 1;
    let closest_lower_proof = SanctionsOrderedMerkleTreeInclusionProof {
        leaf: 0,
        leaf_index: 0,
        sibling_path: [
            2205093791139529737741811388582348022582736433331838106133603722207759128,
            4489263594124270894530400946102719509079258257180881231249118637515264545903,
            17449497805207534876569002585234305995050406065845834440365333063916600323909,
            3089425337917821331814794906895641331148154017691025985937600080581712015475,
            13970263459333343035382044261294475900530405487305345986576605335210027723567,
            18358999910891263669505539030315832131103355888151532871657032722581453584839,
            7257874057037237797347019838971651572458857009509915770016667826449762646959,
            11664286016979532057761756073129395423866681904612719384711871729453089033155,
            7002547648538884744416604405158810952049491083344768535185233280309708958911,
            18595915292666763401374602714297027216946960692263335289755760497749212697481,
            16040901874891594105769056985873171739376547758204991251116264304843356120292,
            9556598420202370822893006104210137641315829257118049066643761989901028732106,
            16781185009437078796036049979060091800631848579406613071322515021218773554762,
            16684379666575197569975881162094932530011128293669323252661093859354006127720,
            720777601321551456724742356376872832235514487302799006897322578639686749258,
        ],
    };
    let closest_upper_proof = SanctionsOrderedMerkleTreeInclusionProof {
        leaf: 2205093791139529737741811388582348022582736433331838106133603722207759128,
        leaf_index: 1,
        sibling_path: [
            0,
            4489263594124270894530400946102719509079258257180881231249118637515264545903,
            17449497805207534876569002585234305995050406065845834440365333063916600323909,
            3089425337917821331814794906895641331148154017691025985937600080581712015475,
            13970263459333343035382044261294475900530405487305345986576605335210027723567,
            18358999910891263669505539030315832131103355888151532871657032722581453584839,
            7257874057037237797347019838971651572458857009509915770016667826449762646959,
            11664286016979532057761756073129395423866681904612719384711871729453089033155,
            7002547648538884744416604405158810952049491083344768535185233280309708958911,
            18595915292666763401374602714297027216946960692263335289755760497749212697481,
            16040901874891594105769056985873171739376547758204991251116264304843356120292,
            9556598420202370822893006104210137641315829257118049066643761989901028732106,
            16781185009437078796036049979060091800631848579406613071322515021218773554762,
            16684379666575197569975881162094932530011128293669323252661093859354006127720,
            720777601321551456724742356376872832235514487302799006897322578639686749258,
        ],
    };

    let proof =
        SanctionsOrderedMerkleTreeProof { left: closest_lower_proof, right: closest_upper_proof };

    ordered_mt_non_membership(root, leaf, proof);
}
