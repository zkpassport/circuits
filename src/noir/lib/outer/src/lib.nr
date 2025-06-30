use poseidon::poseidon2::Poseidon2;

global PROOF_SIZE: u32 = 456;
global VKEY_SIZE: u32 = 112;

pub fn prepare_integrity_check_inputs<let DATE_LEN: u32>(
    current_date: str<DATE_LEN>,
    comm_in: Field,
    comm_out: Field,
) -> [Field; DATE_LEN + 2] {
    let date_bytes: [u8; DATE_LEN] = current_date.as_bytes();
    let mut result: [Field; 2 + DATE_LEN] = [0; 2 + DATE_LEN];
    for i in 0..DATE_LEN {
        result[i] = date_bytes[i] as Field;
    }
    result[DATE_LEN] = comm_in;
    result[DATE_LEN + 1] = comm_out;
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
