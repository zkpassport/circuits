// c.t. /self/noir/crates/dg1/src/utils/
use std::hash::poseidon2::Poseidon2;
use crate::types::{SanctionsOrderedMerkleTreeInclusionProof, SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH, SanctionsOrderedMerkleTreeProof};

///
/// Ordered Merkle Tree Inclusion Proof
///
/// Performs a normal merkle tree inclusion proof
///
pub fn ordered_mt_verify_inclusion(
    root: Field,
    inclusion_proof: SanctionsOrderedMerkleTreeInclusionProof,
) {
    let path_in_bits: [u1; SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH] = inclusion_proof.leaf_index.to_be_bits::<SANCTIONS_ORDERED_MERKLE_TREE_LEAF_DEPTH>();

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

pub fn ordered_mt_non_membership(
    root: Field,
    leaf: Field,
    proof: SanctionsOrderedMerkleTreeProof,
){
    // Perform inclusion checks for bothe the closest upper and the closest lower
    ordered_mt_verify_inclusion(root, proof.left);
    ordered_mt_verify_inclusion(root, proof.right);

    // Check that the closest upper and closest lower are lower / greater than the leaf value
    assert(proof.left.leaf.lt(leaf));
    assert(leaf.lt(proof.right.leaf));

    // Check that their indexes are adjacent
    assert(proof.left.leaf_index + 1 == proof.right.leaf_index);
}

// TODO(md): test this method on the large tree of full depth

#[test(should_fail)]
fn test_ordered_mt_non_membership() {
    // Run yarn generate-sanction-test-data to generate the test data
    // const passportNoAndCountrySMT = await AsyncOrderedMT.fromSerialized(passportNoAndCountryJson, poseidon2)
    // const passportNoAndCountryNonMembershipProof = await passportNoAndCountrySMT.createNonMembershipProof(1n);
    // console.log(passportNoAndCountryNonMembershipProof);

    let root = 4587381064057297507151690651171104724648004732356018424363520949016526295807;
    let leaf = 1;
    let closest_lower_proof = SanctionsOrderedMerkleTreeInclusionProof {
        leaf: 0,
        leaf_index: 0,
        sibling_path: [
            // TODO: the last element in the silbing path should not be the item itself - else we have an issue - 
            2205093791139529737741811388582348022582736433331838106133603722207759128,
            4489263594124270894530400946102719509079258257180881231249118637515264545903,
            17449497805207534876569002585234305995050406065845834440365333063916600323909,
            3089425337917821331814794906895641331148154017691025985937600080581712015475,
            3162539785713891229889803023287558561090005953049942131836435261579309446418,
            4212214425891629388983602917795998803864501512343930557916009292880813919217,
            495852450069293914152116566362821257146737069873276715232466061648151260873,
            21789647988432865607962962837744731184379912577955434669473705006954529897156,
            7310754859706857834747282065863534133581333861137410790446686622477808335289,
            6946980024737789974678441673135333191716399710595068515917414509831606289641,
            6820008724807008385676616067296686012752453531745927302876104566670233246381,
            15318764204341323548131784609288204143936917763539762099075611752249016805480,
            17110486705156693385477855439559097451958311674730202621176701173452078128476,
            10503998961605368431340715288149409141731570720122598863418105270922137068865
        ],
    };
    let closest_upper_proof = SanctionsOrderedMerkleTreeInclusionProof {
        leaf: 22194102214569408510560606408833390162749466612643657912057820208312980445,
        leaf_index: 1,
        sibling_path: [
            0,
            4489263594124270894530400946102719509079258257180881231249118637515264545903,
            17449497805207534876569002585234305995050406065845834440365333063916600323909,
            3089425337917821331814794906895641331148154017691025985937600080581712015475,
            3162539785713891229889803023287558561090005953049942131836435261579309446418,
            4212214425891629388983602917795998803864501512343930557916009292880813919217,
            495852450069293914152116566362821257146737069873276715232466061648151260873,
            21789647988432865607962962837744731184379912577955434669473705006954529897156,
            7310754859706857834747282065863534133581333861137410790446686622477808335289,
            6946980024737789974678441673135333191716399710595068515917414509831606289641,
            6820008724807008385676616067296686012752453531745927302876104566670233246381,
            15318764204341323548131784609288204143936917763539762099075611752249016805480,
            17110486705156693385477855439559097451958311674730202621176701173452078128476,
            10503998961605368431340715288149409141731570720122598863418105270922137068865
        ],
    };

    let proof = SanctionsOrderedMerkleTreeProof {
        left: closest_lower_proof,
        right: closest_upper_proof,
    };

    ordered_mt_non_membership(root, leaf, proof);
}
