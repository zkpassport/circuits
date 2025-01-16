//use std::hash::pedersen_hash;
use std::hash::poseidon2::Poseidon2;
use utils::PASSPORT_MRZ_COUNTRY_INDEX;

pub global CSC_CERT_TYPE: Field = 1;
pub global DSC_CERT_TYPE: Field = 2;

pub fn calculate_scoped_nullifier(
    private_nullifier: Field,
    service_scope: Field,
    service_subscope: Field,
) -> Field {
    Poseidon2::hash([private_nullifier, service_scope, service_subscope], 3)
}

pub fn calculate_certificate_registry_leaf<let N: u32>(
    registry_id: Field,
    cert_type: Field,
    country: str<3>,
    csc_pubkey: [u8; N],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; N + 5] = [0; N + 5];
    result[0] = registry_id as Field;
    result[1] = cert_type as Field;
    result[2] = country_bytes[0] as Field;
    result[3] = country_bytes[1] as Field;
    result[4] = country_bytes[2] as Field;
    for i in 0..N {
        result[i + 5] = csc_pubkey[i] as Field;
    }
    Poseidon2::hash(result, N + 5)
}

pub fn get_country_from_dg1(dg1: [u8; 95]) -> str<3> {
    // There 5 padding bytes in the dg1 before the actual MRZ
    let country_offset = 5 + PASSPORT_MRZ_COUNTRY_INDEX;
    let mut country_bytes: [u8; 3] = [0; 3];
    for i in 0..3 {
        country_bytes[i] = dg1[country_offset + i];
    }
    country_bytes.as_str_unchecked()
}

pub fn hash_salt_country_tbs<let TBS_MAX_SIZE: u32>(
    salt: Field,
    country: str<3>,
    tbs: [u8; TBS_MAX_SIZE],
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; TBS_MAX_SIZE + 4] = [0; TBS_MAX_SIZE + 4];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..TBS_MAX_SIZE {
        result[4 + i] = tbs[i] as Field;
    }
    Poseidon2::hash(result, TBS_MAX_SIZE + 4)
}

pub fn hash_salt_dg1_private_nullifier<let N: u32>(
    salt: Field,
    dg1: [u8; N],
    private_nullifier: Field,
) -> Field {
    let mut result: [Field; N + 2] = [0; N + 2];
    result[0] = salt as Field;
    for i in 0..N {
        result[1 + i] = dg1[i] as Field;
    }
    result[1 + N] = private_nullifier;
    Poseidon2::hash(result, N + 2)
}

pub fn calculate_private_nullifier<let DG1: u32, let SIG: u32>(
    dg1: [u8; DG1],
    sod_sig: [u8; SIG],
) -> Field {
    let mut result: [Field; DG1 + SIG] = [0; DG1 + SIG];
    for i in 0..DG1 {
        result[i] = dg1[i] as Field;
    }
    for i in 0..SIG {
        result[DG1 + i] = sod_sig[i] as Field;
    }
    Poseidon2::hash(result, DG1 + SIG)
}

pub fn hash_salt_country_signed_attr_dg1_private_nullifier<let SA: u32>(
    salt: Field,
    country: str<3>,
    signed_attr: [u8; SA],
    signed_attr_size: Field,
    dg1: [u8; 95],
    private_nullifier: Field,
) -> Field {
    let country_bytes: [u8; 3] = country.as_bytes();
    let mut result: [Field; SA + 101] = [0; SA + 101];
    result[0] = salt as Field;
    result[1] = country_bytes[0] as Field;
    result[2] = country_bytes[1] as Field;
    result[3] = country_bytes[2] as Field;
    for i in 0..SA {
        result[4 + i] = signed_attr[i] as Field;
    }
    result[4 + SA] = signed_attr_size;
    for i in 0..95 {
        result[4 + SA + 1 + i] = dg1[i] as Field;
    }
    result[4 + SA + 1 + 95] = private_nullifier;
    Poseidon2::hash(result, SA + 101)
}

// Returns the merkle root of the tree from the provided leaf, index and hash_path, using the Poseidon2 hash function
// Arity is expected to be 2 and the the tree depth is equal to the hash_path array length
pub fn compute_merkle_root<let N: u32>(leaf: Field, index: Field, hash_path: [Field; N]) -> Field {
    let index_bits: [u1; N] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = Poseidon2::hash([hash_left, hash_right], 2);
    }
    current
}

#[test]
fn test_compute_merkle_root1() {
    let leaf = 0x2fe190f39de3fcf4cbc2eb334d0dc76e4d06f2350aa6056c91ff5f11ded9fb4a;
    let index = 0;
    let hash_path = [
        0x00,
        0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1,
        0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290,
        0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20,
        0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e,
        0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf,
        0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76,
        0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b,
        0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1,
        0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972,
        0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686,
        0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7,
        0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73,
        0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1
    ];
    let root = compute_merkle_root(leaf, index, hash_path);
    assert(root == 0x0742857aba0058b2167c4ac94fede8ec480600911aa871153b988c3f71095449);
}

#[test]
fn test_compute_merkle_root2() {
    let e00 = Poseidon2::hash([1], 1);
    let e01 = Poseidon2::hash([1], 1);
    let e02 = Poseidon2::hash([1], 1);
    let e03 = Poseidon2::hash([1], 1);
    assert(e00 == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373);

    let e10 = Poseidon2::hash([e00, e01], 2);
    let e11 = Poseidon2::hash([e02, e03], 2);
    assert(e10 == 0x113d8ff59c2e15d711241797c380264e39dc1b9e00f2713e707d8d7773b6d912);

    let expected_root = Poseidon2::hash([e10, e11], 2);
    assert(expected_root == 0x0f4f16b234c1d5054b15d408282cb45ba6c10a629fe068e7f3cc253ceae4f08d);

    let hash_path = [e01, e10];
    assert(hash_path == [
        0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
        0x113d8ff59c2e15d711241797c380264e39dc1b9e00f2713e707d8d7773b6d912
    ]);

    let leaf = Poseidon2::hash([1], 1);
    let index = 0;
    let root = compute_merkle_root(leaf, index, hash_path);
    assert(root == 0x0f4f16b234c1d5054b15d408282cb45ba6c10a629fe068e7f3cc253ceae4f08d);
}
