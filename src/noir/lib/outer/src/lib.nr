use poseidon::poseidon2::Poseidon2;

global PROOF_SIZE: u32 = 458;
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
    // The disclosure circuits' public input order — a contract the outer mains assert on by index:
    // [0] comm_in, [1] current_date, [2] service_scope, [3] service_subscope,
    // [4] param_commitment, [5] nullifier_type, [6] scoped_nullifier, [7] oprf_pk_hash
    pub public_inputs: [Field; 8],
    pub key_hash: Field,
    // Hash path for circuit D key hash in the sub-circuit merkle tree
    pub tree_hash_path: [Field; 12],
    // Index of circuit D key hash in the sub-circuit merkle tree
    pub tree_index: Field,
}
