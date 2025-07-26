use poseidon::poseidon2::Poseidon2;

global PROOF_SIZE: u32 = 508;
global VKEY_SIZE: u32 = 115;

pub fn prepare_integrity_check_inputs(
    timestamp: u32,
    comm_in: Field,
    comm_out: Field,
) -> [Field; 3] {
    let mut result: [Field; 3] = [0; 3];
    result[0] = timestamp as Field;
    result[1] = comm_in;
    result[2] = comm_out;
    result
}

pub fn prepare_disclosure_inputs(
    comm_in: Field,
    param_commitment: Field,
    service_scope: Field,
    service_subscope: Field,
    scoped_nullifier: Field,
) -> [Field; 5] {
    let mut result: [Field; 5] = [0; 5];
    result[0] = comm_in;
    result[1] = service_scope;
    result[2] = service_subscope;
    result[3] = param_commitment;
    result[4] = scoped_nullifier;
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
    pub public_inputs: [Field; 1],
    pub key_hash: Field,
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}
