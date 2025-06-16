// c.t. /self/noir/crates/dg1/src/utils/
fn binary_merkle_root<let N: u32>(
    leaf: Field,
    depth: u32,
    indices: [u1; N],
    siblings: [Field; N],
) -> Field {
    let mut nodes: [Field; N + 1] = [0; N + 1];
    nodes[0] = leaf;

    let mut root = 0;

    for i in 0..N {
        let isDepth = if i == depth { 1 } else { 0 };

        root += isDepth * nodes[i];

        let child_nodes = if indices[i] == 0 {
            [nodes[i], siblings[i]]
        } else {
            [siblings[i], nodes[i]]
        };

        nodes[i + 1] = std::hash::poseidon2::Poseidon2::hash(child_nodes, 2);
    }

    let isDepth = if N == depth { 1 } else { 0 };
    root += isDepth * nodes[N];

    root
}

fn siblings_length<let N: u32>(siblings: [Field; N]) -> u32 {
    let mut non_zero_found = 0;
    let mut total = 0;

    for i in 0..N {
        if siblings[N - 1 - i] != 0 {
            non_zero_found = 1;
        }

        total += non_zero_found;
    }

    total
}

pub fn smt_verify<let N: u32>(
    virtualValue: Field,
    value: Field,
    root: Field,
    siblings: [Field; N],
    check_inclusion: bool,
) -> bool {
    let depth = siblings_length(siblings);

    let path_in_bits = virtualValue.to_be_bits::<N>();
    let mut path: [u1; N] = [0; N];

    //move the last "depth" number of bits from path_in_bits to the starting of path
    assert(depth < N);
    for i in 0..depth {
        path[i] = path_in_bits[path_in_bits.len() - depth + i];
    }
    let leaf = std::hash::poseidon2::Poseidon2::hash([value, 1, 1], 3);

    let leaf_or_zero = if value == 0 { 0 } else { leaf };

    let computed_root = binary_merkle_root(leaf_or_zero, depth, path, siblings);
    let computed_root_is_valid = computed_root == root;

    let virtual_leaf = std::hash::poseidon2::Poseidon2::hash([virtualValue, 1, 1], 3);
    let are_leafs_valid = virtual_leaf == leaf;

    let is_mode_valid = check_inclusion == are_leafs_valid;

    is_mode_valid & computed_root_is_valid
}

#[test(should_fail)]
fn test_smt_verify_non_membership() {
    // const smt = new SMT(poseidon2, /*bigNumbers=*/ true)
    // await smt.add(0n, 1n);
    // await smt.add(1n, 1n);
    // await smt.add(3n, 1n);

    // console.log(await smt.createProof(3n));

    let root = 8173855144959561491228669024985303959760886376928631371026390543753247254655;
    let virtual_value = 5;
    let leaf = 1;
    let mut siblings: [Field; 254] = [0; 254];
    siblings[0] = 17995823880102478500203231984351592100342421224652575177474080420521335032391;
    siblings[1] = 6251068641219821617228532485380646097274252458374366123561775799484560721534;

    assert(smt_verify(virtual_value, leaf, root, siblings, false));
}
