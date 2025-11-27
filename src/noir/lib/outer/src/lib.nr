use poseidon::poseidon2::Poseidon2;

global PROOF_SIZE: u32 = 508;
global VKEY_SIZE: u32 = 115;

pub fn prepare_integrity_check_inputs(
    comm_in: Field,
    comm_out: Field,
) -> [Field; 2] {
    let mut result: [Field; 2] = [0; 2];
    result[0] = comm_in;
    result[1] = comm_out;
    result
}

pub fn prepare_disclosure_inputs(
    comm_in: Field,
    current_date: u64,
    param_commitment: Field,
    service_scope: Field,
    service_subscope: Field,
    nullifier_type: Field,
    scoped_nullifier: Field,
) -> [Field; 7] {
    let mut result: [Field; 7] = [0; 7];
    result[0] = comm_in;
    result[1] = current_date as Field;
    result[2] = service_scope;
    result[3] = service_subscope;
    result[4] = param_commitment;
    result[5] = nullifier_type;
    result[6] = scoped_nullifier;
    result
}

pub fn poseidon2_hash<let INPUT_LEN: u32>(input: [Field; INPUT_LEN]) -> Field {
    Poseidon2::hash(input, INPUT_LEN)
}

pub struct CSCtoDSCProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    // Excluding the certificate registry root
    // which is passed separately
    pub public_inputs: [Field; 1],
    pub key_hash: Field,
    // Hash path for circuit A key hash in the sub-circuit merkle tree
    // Allows for up to 4,096 leaves
    pub tree_hash_path: [Field; 12],
    // Index of circuit A key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct DSCtoIDDataProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    pub public_inputs: [Field; 2],
    pub key_hash: Field,
    // Hash path for circuit B key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit B key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct IntegrityCheckProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    pub public_inputs: [Field; 2],
    pub key_hash: Field,
    // Hash path for circuit C key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit C key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}

pub struct DisclosureProof {
    pub vkey: [Field; VKEY_SIZE],
    pub proof: [Field; PROOF_SIZE],
    pub public_inputs: [Field; 2],
    pub key_hash: Field,
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}
